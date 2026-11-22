using System.Globalization;
using Microsoft.Data.Sqlite;
using StartupGuard.Core.Models;

namespace StartupGuard.Core.Storage;

/// <summary>
/// SQLite 深度规则、多态别名集、互斥负样本对与审计日志持久化仓库
/// </summary>
public sealed class SqliteRuleRepository : IDisposable
{
    private readonly string _connectionString;

    public SqliteRuleRepository(string dbFilePath)
    {
        string? dir = Path.GetDirectoryName(dbFilePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbFilePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Default,
            DefaultTimeout = 15,
            Pooling = true,
            ForeignKeys = true
        }.ToString();

        InitializeSchema();
    }

    private void InitializeSchema()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS Rules (
                RuleId INTEGER PRIMARY KEY AUTOINCREMENT,
                DisplayName TEXT NOT NULL,
                Category INTEGER NOT NULL,
                ActionType INTEGER NOT NULL,
                RuleMode INTEGER NOT NULL,
                ConfidenceThreshold REAL DEFAULT 85.0,
                EvolutionCount INTEGER DEFAULT 0,
                HasSignature INTEGER DEFAULT 0,
                SignerSubject TEXT,
                RootCertThumbprint TEXT,
                OriginalFilename TEXT,
                ProductName TEXT,
                CompanyName TEXT,
                InternalName TEXT,
                NormalizedPath TEXT,
                RawCommand TEXT,
                LocationKey TEXT,
                CommandLineArgs TEXT,
                ImpHash TEXT,
                IconPHash INTEGER DEFAULT 0,
                CurrentMD5 TEXT NOT NULL,
                CurrentSHA256 TEXT NOT NULL,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS RuleAliases (
                AliasId INTEGER PRIMARY KEY AUTOINCREMENT,
                RuleId INTEGER NOT NULL,
                ObservedMD5 TEXT NOT NULL,
                ObservedPath TEXT NOT NULL,
                SignerSubject TEXT,
                CommandLineArgs TEXT,
                AdoptedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(RuleId) REFERENCES Rules(RuleId) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS NegativePairs (
                PairId INTEGER PRIMARY KEY AUTOINCREMENT,
                RuleId INTEGER NOT NULL,
                RejectedMD5 TEXT NOT NULL,
                RejectedPath TEXT NOT NULL,
                RejectedSigner TEXT,
                Reason TEXT,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(RuleId) REFERENCES Rules(RuleId) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS RuleWeights (
                RuleId INTEGER PRIMARY KEY,
                W_Signature REAL DEFAULT 30.0,
                W_PEMetadata REAL DEFAULT 25.0,
                W_Path REAL DEFAULT 20.0,
                W_RegistryKey REAL DEFAULT 15.0,
                W_Args REAL DEFAULT 5.0,
                W_ImpHash REAL DEFAULT 5.0,
                FOREIGN KEY(RuleId) REFERENCES Rules(RuleId) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS AuditLogs (
                LogId INTEGER PRIMARY KEY AUTOINCREMENT,
                RuleId INTEGER,
                EventTime DATETIME DEFAULT CURRENT_TIMESTAMP,
                Category INTEGER NOT NULL,
                TargetProgram TEXT NOT NULL,
                TargetLocation TEXT NOT NULL,
                OldState TEXT,
                NewState TEXT,
                ActionTaken TEXT NOT NULL,
                MatchedScore REAL,
                DiagnosticText TEXT,
                SourceProcess TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS ItemNotes (
                LocationKey TEXT PRIMARY KEY,
                Note TEXT NOT NULL,
                UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS ItemProvenance (
                LocationKey TEXT PRIMARY KEY,
                SourceProcess TEXT NOT NULL,
                UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS KnownBaselineItems (
                LocationKey TEXT PRIMARY KEY COLLATE NOCASE,
                Category INTEGER NOT NULL,
                TargetBinaryPath TEXT NOT NULL DEFAULT '',
                NormalizedPath TEXT NOT NULL DEFAULT '',
                RawState TEXT NOT NULL DEFAULT '',
                FileLastWriteUtcTicks INTEGER NOT NULL DEFAULT 0,
                FileLength INTEGER NOT NULL DEFAULT 0,
                FirstSeenUtc TEXT NOT NULL,
                LastSeenUtc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_rules_md5 ON Rules(CurrentMD5);
            CREATE INDEX IF NOT EXISTS idx_aliases_rule ON RuleAliases(RuleId);
            CREATE INDEX IF NOT EXISTS idx_negative_lookup ON NegativePairs(RuleId, RejectedMD5);
            CREATE INDEX IF NOT EXISTS idx_audit_location ON AuditLogs(TargetLocation);
            """;
        cmd.ExecuteNonQuery();

        // 兼容升级已存在的旧表（补充 RawCommand / SourceProcess 列）
        try
        {
            using var alterCmd = conn.CreateCommand();
            alterCmd.CommandText = "ALTER TABLE Rules ADD COLUMN RawCommand TEXT DEFAULT '';";
            alterCmd.ExecuteNonQuery();
        }
        catch
        {
            // Column already exists
        }
        try
        {
            using var alterAuditCmd = conn.CreateCommand();
            alterAuditCmd.CommandText = "ALTER TABLE AuditLogs ADD COLUMN SourceProcess TEXT DEFAULT '';";
            alterAuditCmd.ExecuteNonQuery();
        }
        catch
        {
            // Column already exists
        }
    }

    public List<RuleRecord> LoadAllRulesWithDetails() => GetAllRulesWithWeightsAndAliases();

    public List<RuleRecord> GetAllRulesWithWeightsAndAliases()
    {
        var rules = new Dictionary<int, RuleRecord>();
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                SELECT r.RuleId, r.DisplayName, r.Category, r.ActionType, r.RuleMode,
                       r.ConfidenceThreshold, r.EvolutionCount, r.HasSignature,
                       r.SignerSubject, r.RootCertThumbprint, r.OriginalFilename,
                       r.ProductName, r.CompanyName, r.InternalName, r.NormalizedPath,
                       r.LocationKey, r.CommandLineArgs, r.ImpHash, r.IconPHash,
                       r.CurrentMD5, r.CurrentSHA256,
                       IFNULL(w.W_Signature, 30.0), IFNULL(w.W_PEMetadata, 25.0),
                       IFNULL(w.W_Path, 20.0), IFNULL(w.W_RegistryKey, 15.0),
                       IFNULL(w.W_Args, 5.0), IFNULL(w.W_ImpHash, 5.0),
                       IFNULL(r.RawCommand, ''),
                       IFNULL(r.UpdatedAt, '')
                FROM Rules r
                LEFT JOIN RuleWeights w ON r.RuleId = w.RuleId;
                """;
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                string normPath = reader.IsDBNull(14) ? string.Empty : reader.GetString(14);
                string rawCmd = reader.IsDBNull(27) ? string.Empty : reader.GetString(27);
                string updatedRaw = reader.IsDBNull(28) ? string.Empty : reader.GetString(28);
                DateTime updatedAt = DateTime.UtcNow;
                if (!string.IsNullOrWhiteSpace(updatedRaw) &&
                    DateTime.TryParse(updatedRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsedUpdated))
                {
                    updatedAt = DateTime.SpecifyKind(parsedUpdated, DateTimeKind.Utc);
                }

                var rule = new RuleRecord
                {
                    RuleId = reader.GetInt32(0),
                    DisplayName = reader.GetString(1),
                    Category = (MonitorCategory)reader.GetByte(2),
                    ActionType = (InterceptionAction)reader.GetByte(3),
                    RuleMode = (RuleMatchMode)reader.GetByte(4),
                    ConfidenceThreshold = reader.GetFloat(5),
                    EvolutionCount = reader.GetInt32(6),
                    HasSignature = reader.GetInt32(7) != 0,
                    SignerSubject = reader.IsDBNull(8) ? string.Empty : reader.GetString(8),
                    RootCertThumbprint = reader.IsDBNull(9) ? string.Empty : reader.GetString(9),
                    OriginalFilename = reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
                    ProductName = reader.IsDBNull(11) ? string.Empty : reader.GetString(11),
                    CompanyName = reader.IsDBNull(12) ? string.Empty : reader.GetString(12),
                    InternalName = reader.IsDBNull(13) ? string.Empty : reader.GetString(13),
                    NormalizedPath = normPath,
                    RawCommand = !string.IsNullOrEmpty(rawCmd) ? rawCmd : normPath,
                    LocationKey = reader.IsDBNull(15) ? string.Empty : reader.GetString(15),
                    CommandLineArgs = reader.IsDBNull(16) ? string.Empty : reader.GetString(16),
                    ImpHash = reader.IsDBNull(17) ? string.Empty : reader.GetString(17),
                    IconPHash = (ulong)reader.GetInt64(18),
                    CurrentMD5 = reader.GetString(19),
                    CurrentSHA256 = reader.GetString(20),
                    UpdatedAt = updatedAt,
                    Weights = new SixDimensionWeights
                    {
                        W_Signature = reader.GetFloat(21),
                        W_PEMetadata = reader.GetFloat(22),
                        W_PathTemplate = reader.GetFloat(23),
                        W_LocationKey = reader.GetFloat(24),
                        W_CommandArgs = reader.GetFloat(25),
                        W_ImpAndPHash = reader.GetFloat(26)
                    }
                };
                rules[rule.RuleId] = rule;
            }
        }

        using (var aliasCmd = conn.CreateCommand())
        {
            aliasCmd.CommandText = "SELECT AliasId, RuleId, ObservedMD5, ObservedPath, SignerSubject, CommandLineArgs FROM RuleAliases;";
            using var reader = aliasCmd.ExecuteReader();
            while (reader.Read())
            {
                int ruleId = reader.GetInt32(1);
                if (rules.TryGetValue(ruleId, out var parent))
                {
                    parent.Aliases.Add(new RuleAliasEntry
                    {
                        AliasId = reader.GetInt32(0),
                        RuleId = ruleId,
                        ObservedMD5 = reader.GetString(2),
                        ObservedNormalizedPath = reader.GetString(3),
                        SignerSubject = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                        CommandLineArgs = reader.IsDBNull(5) ? string.Empty : reader.GetString(5)
                    });
                }
            }
        }

        return [.. rules.Values];
    }

    public bool IsNegativePair(int ruleId, string targetMd5, string normalizedPath)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT COUNT(1) FROM NegativePairs
            WHERE RuleId = $ruleId
              AND ((RejectedMD5 != '' AND LOWER(RejectedMD5) = LOWER($md5))
                   OR (RejectedPath != '' AND LOWER(RejectedPath) = LOWER($path)));
            """;
        cmd.Parameters.AddWithValue("$ruleId", ruleId);
        cmd.Parameters.AddWithValue("$md5", targetMd5 ?? string.Empty);
        cmd.Parameters.AddWithValue("$path", normalizedPath ?? string.Empty);
        long count = (long)(cmd.ExecuteScalar() ?? 0L);
        return count > 0;
    }

    public int SaveOrUpdateRule(RuleRecord rule) => InsertOrUpdateRule(rule);

    public int InsertOrUpdateRule(RuleRecord rule)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var tx = conn.BeginTransaction();

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        if (rule.RuleId <= 0)
        {
            cmd.CommandText = """
                INSERT INTO Rules (
                    DisplayName, Category, ActionType, RuleMode, ConfidenceThreshold,
                    EvolutionCount, HasSignature, SignerSubject, RootCertThumbprint,
                    OriginalFilename, ProductName, CompanyName, InternalName,
                    NormalizedPath, RawCommand, LocationKey, CommandLineArgs, ImpHash, IconPHash,
                    CurrentMD5, CurrentSHA256
                ) VALUES (
                    $name, $cat, $act, $mode, $thresh, $evo, $hasSig, $sigSubj, $thumb,
                    $origName, $prodName, $compName, $intName, $normPath, $rawCmd, $locKey,
                    $args, $imp, $phash, $md5, $sha
                );
                SELECT last_insert_rowid();
                """;
        }
        else
        {
            cmd.CommandText = """
                UPDATE Rules SET
                    DisplayName = $name, Category = $cat, ActionType = $act, RuleMode = $mode,
                    ConfidenceThreshold = $thresh, EvolutionCount = $evo, HasSignature = $hasSig,
                    SignerSubject = $sigSubj, RootCertThumbprint = $thumb,
                    OriginalFilename = $origName, ProductName = $prodName, CompanyName = $compName,
                    InternalName = $intName, NormalizedPath = $normPath, RawCommand = $rawCmd, LocationKey = $locKey,
                    CommandLineArgs = $args, ImpHash = $imp, IconPHash = $phash,
                    CurrentMD5 = $md5, CurrentSHA256 = $sha, UpdatedAt = CURRENT_TIMESTAMP
                WHERE RuleId = $id;
                SELECT CASE WHEN changes() > 0 THEN $id ELSE 0 END;
                """;
            cmd.Parameters.AddWithValue("$id", rule.RuleId);
        }

        int id;
        if (rule.RuleId <= 0)
        {
            cmd.Parameters.AddWithValue("$name", rule.DisplayName ?? string.Empty);
            cmd.Parameters.AddWithValue("$cat", (byte)rule.Category);
            cmd.Parameters.AddWithValue("$act", (byte)rule.ActionType);
            cmd.Parameters.AddWithValue("$mode", (byte)rule.RuleMode);
            cmd.Parameters.AddWithValue("$thresh", rule.ConfidenceThreshold);
            cmd.Parameters.AddWithValue("$evo", rule.EvolutionCount);
            cmd.Parameters.AddWithValue("$hasSig", rule.HasSignature ? 1 : 0);
            cmd.Parameters.AddWithValue("$sigSubj", rule.SignerSubject ?? string.Empty);
            cmd.Parameters.AddWithValue("$thumb", rule.RootCertThumbprint ?? string.Empty);
            cmd.Parameters.AddWithValue("$origName", rule.OriginalFilename ?? string.Empty);
            cmd.Parameters.AddWithValue("$prodName", rule.ProductName ?? string.Empty);
            cmd.Parameters.AddWithValue("$compName", rule.CompanyName ?? string.Empty);
            cmd.Parameters.AddWithValue("$intName", rule.InternalName ?? string.Empty);
            cmd.Parameters.AddWithValue("$normPath", rule.NormalizedPath ?? string.Empty);
            cmd.Parameters.AddWithValue("$rawCmd", !string.IsNullOrEmpty(rule.RawCommand) ? rule.RawCommand : (rule.NormalizedPath ?? string.Empty));
            cmd.Parameters.AddWithValue("$locKey", rule.LocationKey ?? string.Empty);
            cmd.Parameters.AddWithValue("$args", rule.CommandLineArgs ?? string.Empty);
            cmd.Parameters.AddWithValue("$imp", rule.ImpHash ?? string.Empty);
            cmd.Parameters.AddWithValue("$phash", (long)rule.IconPHash);
            cmd.Parameters.AddWithValue("$md5", rule.CurrentMD5 ?? string.Empty);
            cmd.Parameters.AddWithValue("$sha", rule.CurrentSHA256 ?? string.Empty);

            id = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
            rule.RuleId = id;
        }
        else
        {
            cmd.Parameters.AddWithValue("$name", rule.DisplayName ?? string.Empty);
            cmd.Parameters.AddWithValue("$cat", (byte)rule.Category);
            cmd.Parameters.AddWithValue("$act", (byte)rule.ActionType);
            cmd.Parameters.AddWithValue("$mode", (byte)rule.RuleMode);
            cmd.Parameters.AddWithValue("$thresh", rule.ConfidenceThreshold);
            cmd.Parameters.AddWithValue("$evo", rule.EvolutionCount);
            cmd.Parameters.AddWithValue("$hasSig", rule.HasSignature ? 1 : 0);
            cmd.Parameters.AddWithValue("$sigSubj", rule.SignerSubject ?? string.Empty);
            cmd.Parameters.AddWithValue("$thumb", rule.RootCertThumbprint ?? string.Empty);
            cmd.Parameters.AddWithValue("$origName", rule.OriginalFilename ?? string.Empty);
            cmd.Parameters.AddWithValue("$prodName", rule.ProductName ?? string.Empty);
            cmd.Parameters.AddWithValue("$compName", rule.CompanyName ?? string.Empty);
            cmd.Parameters.AddWithValue("$intName", rule.InternalName ?? string.Empty);
            cmd.Parameters.AddWithValue("$normPath", rule.NormalizedPath ?? string.Empty);
            cmd.Parameters.AddWithValue("$rawCmd", !string.IsNullOrEmpty(rule.RawCommand) ? rule.RawCommand : (rule.NormalizedPath ?? string.Empty));
            cmd.Parameters.AddWithValue("$locKey", rule.LocationKey ?? string.Empty);
            cmd.Parameters.AddWithValue("$args", rule.CommandLineArgs ?? string.Empty);
            cmd.Parameters.AddWithValue("$imp", rule.ImpHash ?? string.Empty);
            cmd.Parameters.AddWithValue("$phash", (long)rule.IconPHash);
            cmd.Parameters.AddWithValue("$md5", rule.CurrentMD5 ?? string.Empty);
            cmd.Parameters.AddWithValue("$sha", rule.CurrentSHA256 ?? string.Empty);

            int updated = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
            if (updated <= 0)
            {
                SharedStorageHelper.LogDiagnostic("SqliteRepo",
                    $"InsertOrUpdateRule skipped non-existent RuleId={rule.RuleId} (name={rule.DisplayName}, loc={rule.LocationKey}).");
                tx.Rollback();
                return 0;
            }
            id = updated;
            rule.RuleId = id;
        }

        using var wCmd = conn.CreateCommand();
        wCmd.Transaction = tx;
        wCmd.CommandText = """
            INSERT INTO RuleWeights (RuleId, W_Signature, W_PEMetadata, W_Path, W_RegistryKey, W_Args, W_ImpHash)
            VALUES ($id, $w1, $w2, $w3, $w4, $w5, $w6)
            ON CONFLICT(RuleId) DO UPDATE SET
                W_Signature = $w1, W_PEMetadata = $w2, W_Path = $w3,
                W_RegistryKey = $w4, W_Args = $w5, W_ImpHash = $w6;
            """;
        wCmd.Parameters.AddWithValue("$id", id);
        wCmd.Parameters.AddWithValue("$w1", rule.Weights.W_Signature);
        wCmd.Parameters.AddWithValue("$w2", rule.Weights.W_PEMetadata);
        wCmd.Parameters.AddWithValue("$w3", rule.Weights.W_PathTemplate);
        wCmd.Parameters.AddWithValue("$w4", rule.Weights.W_LocationKey);
        wCmd.Parameters.AddWithValue("$w5", rule.Weights.W_CommandArgs);
        wCmd.Parameters.AddWithValue("$w6", rule.Weights.W_ImpAndPHash);
        wCmd.ExecuteNonQuery();

        tx.Commit();
        return id;
    }

    /// <summary>
    /// 删除指定规则及其关联的别名、负样本对与权重记录
    /// </summary>
    public bool DeleteRule(int ruleId)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var tx = conn.BeginTransaction();

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            PRAGMA foreign_keys = ON;
            DELETE FROM RuleAliases WHERE RuleId = $id;
            DELETE FROM NegativePairs WHERE RuleId = $id;
            DELETE FROM RuleWeights WHERE RuleId = $id;
            DELETE FROM Rules WHERE RuleId = $id;
            """;
        cmd.Parameters.AddWithValue("$id", ruleId);
        int affected = cmd.ExecuteNonQuery();
        tx.Commit();
        return affected > 0;
    }

    /// <summary>
    /// 更新规则的拦截动作、记忆模式与可信度匹配阈值
    /// </summary>
    public bool UpdateRuleActionAndMode(int ruleId, InterceptionAction action, RuleMatchMode mode, float confidenceThreshold)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE Rules SET
                ActionType = $act,
                RuleMode = $mode,
                ConfidenceThreshold = $thresh,
                UpdatedAt = CURRENT_TIMESTAMP
            WHERE RuleId = $id;
            """;
        cmd.Parameters.AddWithValue("$id", ruleId);
        cmd.Parameters.AddWithValue("$act", (byte)action);
        cmd.Parameters.AddWithValue("$mode", (byte)mode);
        cmd.Parameters.AddWithValue("$thresh", Math.Clamp(confidenceThreshold, 55.0f, 98.0f));
        return cmd.ExecuteNonQuery() > 0;
    }

    /// <summary>
    /// 补全既有规则缺失的文件哈希与 Authenticode 签名信息（如早期未展开 \SystemRoot\ 的驱动规则）
    /// </summary>
    public bool UpdateRuleBinaryMetadata(
        int ruleId,
        string md5,
        string sha256,
        bool hasSignature,
        string signerSubject,
        string rootThumbprint)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE Rules SET
                CurrentMD5 = CASE WHEN IFNULL(CurrentMD5, '') = '' THEN $md5 ELSE CurrentMD5 END,
                CurrentSHA256 = CASE WHEN IFNULL(CurrentSHA256, '') = '' THEN $sha ELSE CurrentSHA256 END,
                HasSignature = CASE WHEN HasSignature = 0 AND $hasSig = 1 THEN 1 ELSE HasSignature END,
                SignerSubject = CASE WHEN IFNULL(SignerSubject, '') = '' THEN $signer ELSE SignerSubject END,
                RootCertThumbprint = CASE WHEN IFNULL(RootCertThumbprint, '') = '' THEN $thumb ELSE RootCertThumbprint END
            WHERE RuleId = $id;
            """;
        cmd.Parameters.AddWithValue("$id", ruleId);
        cmd.Parameters.AddWithValue("$md5", md5 ?? string.Empty);
        cmd.Parameters.AddWithValue("$sha", sha256 ?? string.Empty);
        cmd.Parameters.AddWithValue("$hasSig", hasSignature ? 1 : 0);
        cmd.Parameters.AddWithValue("$signer", signerSubject ?? string.Empty);
        cmd.Parameters.AddWithValue("$thumb", rootThumbprint ?? string.Empty);
        return cmd.ExecuteNonQuery() > 0;
    }

    /// <summary>
    /// 更新规则的六维演化权重、阈值、演化次数及最新哈希指纹
    /// </summary>
    public bool UpdateRuleWeightsAndThreshold(
        int ruleId,
        SixDimensionWeights weights,
        float newThreshold,
        int evolutionCount = -1,
        string? newMd5 = null,
        string? newSha256 = null)
    {
        if (ruleId <= 0)
            return false;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var tx = conn.BeginTransaction();

        using (var wCmd = conn.CreateCommand())
        {
            wCmd.Transaction = tx;
            wCmd.CommandText = """
                INSERT INTO RuleWeights (RuleId, W_Signature, W_PEMetadata, W_Path, W_RegistryKey, W_Args, W_ImpHash)
                VALUES ($id, $w1, $w2, $w3, $w4, $w5, $w6)
                ON CONFLICT(RuleId) DO UPDATE SET
                    W_Signature = $w1, W_PEMetadata = $w2, W_Path = $w3,
                    W_RegistryKey = $w4, W_Args = $w5, W_ImpHash = $w6;
                """;
            wCmd.Parameters.AddWithValue("$id", ruleId);
            wCmd.Parameters.AddWithValue("$w1", weights.W_Signature);
            wCmd.Parameters.AddWithValue("$w2", weights.W_PEMetadata);
            wCmd.Parameters.AddWithValue("$w3", weights.W_PathTemplate);
            wCmd.Parameters.AddWithValue("$w4", weights.W_LocationKey);
            wCmd.Parameters.AddWithValue("$w5", weights.W_CommandArgs);
            wCmd.Parameters.AddWithValue("$w6", weights.W_ImpAndPHash);
            wCmd.ExecuteNonQuery();
        }

        using (var rCmd = conn.CreateCommand())
        {
            rCmd.Transaction = tx;
            rCmd.CommandText = """
                UPDATE Rules SET
                    ConfidenceThreshold = $thresh,
                    EvolutionCount = CASE WHEN $evo >= 0 THEN $evo ELSE EvolutionCount END,
                    CurrentMD5 = CASE WHEN $md5 IS NOT NULL THEN $md5 ELSE CurrentMD5 END,
                    CurrentSHA256 = CASE WHEN $sha IS NOT NULL THEN $sha ELSE CurrentSHA256 END,
                    UpdatedAt = CURRENT_TIMESTAMP
                WHERE RuleId = $id;
                """;
            rCmd.Parameters.AddWithValue("$id", ruleId);
            rCmd.Parameters.AddWithValue("$thresh", newThreshold);
            rCmd.Parameters.AddWithValue("$evo", evolutionCount);
            rCmd.Parameters.AddWithValue("$md5", newMd5 is not null ? newMd5 : DBNull.Value);
            rCmd.Parameters.AddWithValue("$sha", newSha256 is not null ? newSha256 : DBNull.Value);
            rCmd.ExecuteNonQuery();
        }

        tx.Commit();
        return true;
    }

    public void AddRuleAlias(int ruleId, RuleAliasEntry alias)
    {
        AddPolymorphicAlias(
            ruleId,
            alias.ObservedMD5,
            alias.ObservedNormalizedPath,
            alias.SignerSubject,
            alias.CommandLineArgs);
    }

    public void AddPolymorphicAlias(int ruleId, string md5, string normalizedPath, string signer, string args)
    {
        if (ruleId <= 0)
            return;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO RuleAliases (RuleId, ObservedMD5, ObservedPath, SignerSubject, CommandLineArgs)
            VALUES ($id, $md5, $path, $sig, $args);
            """;
        cmd.Parameters.AddWithValue("$id", ruleId);
        cmd.Parameters.AddWithValue("$md5", md5 ?? string.Empty);
        cmd.Parameters.AddWithValue("$path", normalizedPath ?? string.Empty);
        cmd.Parameters.AddWithValue("$sig", signer ?? string.Empty);
        cmd.Parameters.AddWithValue("$args", args ?? string.Empty);
        cmd.ExecuteNonQuery();
    }

    public void AddNegativePair(int ruleId, string rejectedMd5, string rejectedPath, string rejectedSigner, string reason)
    {
        if (ruleId <= 0)
            return;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO NegativePairs (RuleId, RejectedMD5, RejectedPath, RejectedSigner, Reason)
            VALUES ($id, $md5, $path, $sig, $reason);
            """;
        cmd.Parameters.AddWithValue("$id", ruleId);
        cmd.Parameters.AddWithValue("$md5", rejectedMd5 ?? string.Empty);
        cmd.Parameters.AddWithValue("$path", rejectedPath ?? string.Empty);
        cmd.Parameters.AddWithValue("$sig", rejectedSigner ?? string.Empty);
        cmd.Parameters.AddWithValue("$reason", reason ?? string.Empty);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// 查询互斥负样本对记录列表
    /// </summary>
    public List<NegativePairRecord> GetNegativePairs(int? ruleId = null)
    {
        var list = new List<NegativePairRecord>();
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        if (ruleId.HasValue)
        {
            cmd.CommandText = """
                SELECT PairId, RuleId, RejectedMD5, RejectedPath, RejectedSigner, Reason, CreatedAt
                FROM NegativePairs
                WHERE RuleId = $rid
                ORDER BY PairId DESC;
                """;
            cmd.Parameters.AddWithValue("$rid", ruleId.Value);
        }
        else
        {
            cmd.CommandText = """
                SELECT PairId, RuleId, RejectedMD5, RejectedPath, RejectedSigner, Reason, CreatedAt
                FROM NegativePairs
                ORDER BY PairId DESC;
                """;
        }

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new NegativePairRecord
            {
                PairId = reader.GetInt32(0),
                RuleId = reader.GetInt32(1),
                RejectedMD5 = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                RejectedPath = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                RejectedSigner = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                Reason = reader.IsDBNull(5) ? string.Empty : reader.GetString(5),
                CreatedAt = reader.IsDBNull(6) ? DateTime.UtcNow : reader.GetDateTime(6)
            });
        }
        return list;
    }

    public void InsertAuditLog(
        int? ruleId,
        MonitorCategory category,
        string program,
        string location,
        string oldState,
        string newState,
        string action,
        double score,
        string diagnostic,
        string sourceProcess = "")
        => WriteAuditLog(ruleId, category, program, location, oldState, newState, action, score, diagnostic, sourceProcess);

    public void InsertAuditLog(AuditLogRecord record)
        => WriteAuditLog(
            record.RuleId,
            record.Category,
            record.TargetProgram,
            record.TargetLocation,
            record.OldState,
            record.NewState,
            record.ActionTaken,
            record.MatchedScore,
            record.DiagnosticText,
            record.SourceProcess);

    public void WriteAuditLog(int? ruleId, MonitorCategory category, string program, string location, string oldState, string newState, string action, double score, string diagnostic, string sourceProcess = "")
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var tx = conn.BeginTransaction();

        string effectiveSourceProc = sourceProcess?.Trim() ?? string.Empty;

        // 若调用方未传入新来源进程，保留既有已知来源
        if (string.IsNullOrEmpty(effectiveSourceProc) && !string.IsNullOrWhiteSpace(location))
        {
            effectiveSourceProc = TryReadExistingProvenance(conn, tx, location);
        }

        // 对同一目标位置及其禁用变体只保留最后一条最终操作日志，避免旧的待审核/等待记录堆积
        if (!string.IsNullOrWhiteSpace(location))
        {
            var variants = ExpandLocationMatchVariants(location);
            using var delCmd = conn.CreateCommand();
            delCmd.Transaction = tx;
            var paramNames = new List<string>(variants.Count);
            for (int i = 0; i < variants.Count; i++)
            {
                string pname = $"$v{i}";
                paramNames.Add($"LOWER({pname})");
                delCmd.Parameters.AddWithValue(pname, variants[i]);
            }
            delCmd.CommandText = $"DELETE FROM AuditLogs WHERE LOWER(TargetLocation) IN ({string.Join(", ", paramNames)});";
            delCmd.ExecuteNonQuery();

            if (!string.IsNullOrEmpty(effectiveSourceProc))
            {
                string canonicalLoc = CanonicalizeLocationForStorage(location);
                using var provCmd = conn.CreateCommand();
                provCmd.Transaction = tx;
                provCmd.CommandText = """
                    INSERT INTO ItemProvenance (LocationKey, SourceProcess, UpdatedAt)
                    VALUES ($loc, $src, CURRENT_TIMESTAMP)
                    ON CONFLICT(LocationKey) DO UPDATE SET SourceProcess = excluded.SourceProcess, UpdatedAt = CURRENT_TIMESTAMP;
                    """;
                provCmd.Parameters.AddWithValue("$loc", canonicalLoc);
                provCmd.Parameters.AddWithValue("$src", effectiveSourceProc);
                provCmd.ExecuteNonQuery();
            }
        }

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO AuditLogs (RuleId, Category, TargetProgram, TargetLocation, OldState, NewState, ActionTaken, MatchedScore, DiagnosticText, SourceProcess)
            VALUES ($rid, $cat, $prog, $loc, $old, $new, $act, $score, $diag, $src);
            """;
        cmd.Parameters.AddWithValue("$rid", ruleId.HasValue ? ruleId.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$cat", (byte)category);
        cmd.Parameters.AddWithValue("$prog", program ?? string.Empty);
        cmd.Parameters.AddWithValue("$loc", (location ?? string.Empty).Trim());
        cmd.Parameters.AddWithValue("$old", oldState ?? string.Empty);
        cmd.Parameters.AddWithValue("$new", newState ?? string.Empty);
        cmd.Parameters.AddWithValue("$act", action ?? string.Empty);
        cmd.Parameters.AddWithValue("$score", score);
        cmd.Parameters.AddWithValue("$diag", diagnostic ?? string.Empty);
        cmd.Parameters.AddWithValue("$src", effectiveSourceProc);
        cmd.ExecuteNonQuery();
        tx.Commit();
    }

    /// <summary>
    /// 获取最近的拦截与自学习审计日志
    /// </summary>
    public List<AuditLogRecord> GetRecentAuditLogs(int limit = 200)
        => QueryAuditLogs(whereClause: null, limit: Math.Max(1, limit));

    /// <summary>
    /// 获取全部处于待审核状态的审计记录（不受最近日志条数上限截断）
    /// </summary>
    public List<AuditLogRecord> GetPendingAuditLogs()
        => QueryAuditLogs(
            whereClause: """
                WHERE LOWER(ActionTaken) LIKE '%pending audit%'
                   OR ActionTaken LIKE '%暂存%'
                   OR ActionTaken LIKE '%待审%'
                   OR ActionTaken LIKE '%先拦截待审%'
                """,
            limit: null);

    private List<AuditLogRecord> QueryAuditLogs(string? whereClause, int? limit)
    {
        var list = new List<AuditLogRecord>();
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        string limitSql = limit.HasValue ? "LIMIT $lim" : string.Empty;
        cmd.CommandText = $"""
            SELECT LogId, RuleId, EventTime, Category, TargetProgram, TargetLocation,
                   OldState, NewState, ActionTaken, MatchedScore, DiagnosticText, SourceProcess
            FROM AuditLogs
            {whereClause ?? string.Empty}
            ORDER BY LogId DESC
            {limitSql};
            """;
        if (limit.HasValue)
            cmd.Parameters.AddWithValue("$lim", limit.Value);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new AuditLogRecord
            {
                LogId = reader.GetInt32(0),
                RuleId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                EventTime = reader.IsDBNull(2) ? DateTime.Now : DateTime.SpecifyKind(reader.GetDateTime(2), DateTimeKind.Utc).ToLocalTime(),
                Category = (MonitorCategory)reader.GetByte(3),
                TargetProgram = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                TargetLocation = reader.IsDBNull(5) ? string.Empty : reader.GetString(5),
                OldState = reader.IsDBNull(6) ? string.Empty : reader.GetString(6),
                NewState = reader.IsDBNull(7) ? string.Empty : reader.GetString(7),
                ActionTaken = reader.IsDBNull(8) ? string.Empty : reader.GetString(8),
                MatchedScore = reader.IsDBNull(9) ? 0.0 : reader.GetDouble(9),
                DiagnosticText = reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
                SourceProcess = reader.IsDBNull(11) ? string.Empty : reader.GetString(11)
            });
        }
        return list;
    }

    public void ClearAuditLogs()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM AuditLogs;";
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// 根据保留天数和最大保留条数自动裁剪审计与拦截日志，防止无节制膨胀
    /// </summary>
    public int PruneAuditLogs(int retentionDays, int maxCount)
    {
        int deleted = 0;
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        if (retentionDays > 0)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM AuditLogs WHERE EventTime < datetime('now', $interval);";
            cmd.Parameters.AddWithValue("$interval", $"-{retentionDays} days");
            deleted += cmd.ExecuteNonQuery();
        }

        if (maxCount > 0)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                DELETE FROM AuditLogs 
                WHERE LogId NOT IN (
                    SELECT LogId FROM AuditLogs 
                    ORDER BY LogId DESC 
                    LIMIT $maxCount
                );
                """;
            cmd.Parameters.AddWithValue("$maxCount", maxCount);
            deleted += cmd.ExecuteNonQuery();
        }

        return deleted;
    }

    /// <summary>
    /// 清空临时释放空间并执行 SQLite VACUUM 与 WAL checkpoint
    /// </summary>
    public void CompactDatabase()
    {
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var walCmd = conn.CreateCommand();
            walCmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            walCmd.ExecuteNonQuery();

            using var vacCmd = conn.CreateCommand();
            vacCmd.CommandText = "VACUUM;";
            vacCmd.ExecuteNonQuery();
        }
        catch { }
    }

    public Dictionary<string, string> GetAllItemNotes()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT LocationKey, Note FROM ItemNotes;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            string key = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
            string note = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
            if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(note))
                map[key] = note;
        }
        return map;
    }

    public string GetItemNote(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey)) return string.Empty;
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Note FROM ItemNotes WHERE LOWER(LocationKey) = LOWER($loc) LIMIT 1;";
        cmd.Parameters.AddWithValue("$loc", locationKey.Trim());
        return cmd.ExecuteScalar()?.ToString() ?? string.Empty;
    }

    public void SaveItemNote(string locationKey, string note)
    {
        if (string.IsNullOrWhiteSpace(locationKey)) return;
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        if (string.IsNullOrWhiteSpace(note))
        {
            cmd.CommandText = "DELETE FROM ItemNotes WHERE LOWER(LocationKey) = LOWER($loc);";
            cmd.Parameters.AddWithValue("$loc", locationKey.Trim());
            cmd.ExecuteNonQuery();
        }
        else
        {
            cmd.CommandText = """
                INSERT INTO ItemNotes (LocationKey, Note, UpdatedAt)
                VALUES ($loc, $note, CURRENT_TIMESTAMP)
                ON CONFLICT(LocationKey) DO UPDATE SET Note = excluded.Note, UpdatedAt = CURRENT_TIMESTAMP;
                """;
            cmd.Parameters.AddWithValue("$loc", locationKey.Trim());
            cmd.Parameters.AddWithValue("$note", note.Trim());
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>
    /// 标准化路径并展开所有注册表根键与右键禁用状态变体（解决 \-ContextMenuHandlers\ 等变体与原始日志位置不一致导致的待审核无法核销问题）
    /// </summary>
    public static List<string> ExpandLocationMatchVariants(string locationKey)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(locationKey))
            return [];

        string baseLoc = locationKey.Trim();
        if (baseLoc.StartsWith(@"计算机\", StringComparison.Ordinal))
            baseLoc = baseLoc[4..];

        var hiveVariants = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { baseLoc };
        static void AddHiveSwap(HashSet<string> target, string input, string a, string b)
        {
            if (input.StartsWith(a, StringComparison.OrdinalIgnoreCase))
                target.Add(b + input[a.Length..]);
            else if (input.StartsWith(b, StringComparison.OrdinalIgnoreCase))
                target.Add(a + input[b.Length..]);
        }

        AddHiveSwap(hiveVariants, baseLoc, @"HKLM\", @"HKEY_LOCAL_MACHINE\");
        AddHiveSwap(hiveVariants, baseLoc, @"HKCU\", @"HKEY_CURRENT_USER\");
        AddHiveSwap(hiveVariants, baseLoc, @"HKCR\", @"HKEY_CLASSES_ROOT\");
        AddHiveSwap(hiveVariants, baseLoc, @"HKU\", @"HKEY_USERS\");

        foreach (string hv in hiveVariants)
        {
            set.Add(hv);
            string swapped = hv
                .Replace(@"\-ContextMenuHandlers\", @"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase)
                .Replace(@"\-DragDropHandlers\", @"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase);
            set.Add(swapped);

            string disabledFolder = swapped
                .Replace(@"\ContextMenuHandlers\", @"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase)
                .Replace(@"\DragDropHandlers\", @"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase);
            set.Add(disabledFolder);

            foreach (string cand in new[] { hv, swapped, disabledFolder })
            {
                int lastSlash = cand.LastIndexOf('\\');
                if (lastSlash >= 0 && lastSlash < cand.Length - 1)
                {
                    string prefix = cand[..(lastSlash + 1)];
                    string leaf = cand[(lastSlash + 1)..];
                    string cleanLeaf = leaf.TrimStart('-');
                    set.Add(prefix + cleanLeaf);
                    set.Add(prefix + "-" + cleanLeaf);
                }
            }
        }

        return [.. set];
    }

    public static string CanonicalizeLocationForStorage(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return string.Empty;

        string s = locationKey.Trim();
        if (s.StartsWith(@"计算机\", StringComparison.Ordinal))
            s = s[4..];

        if (s.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase))
            s = @"HKLM\" + s[@"HKEY_LOCAL_MACHINE\".Length..];
        else if (s.StartsWith(@"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase))
            s = @"HKCU\" + s[@"HKEY_CURRENT_USER\".Length..];
        else if (s.StartsWith(@"HKEY_CLASSES_ROOT\", StringComparison.OrdinalIgnoreCase))
            s = @"HKCR\" + s[@"HKEY_CLASSES_ROOT\".Length..];
        else if (s.StartsWith(@"HKEY_USERS\", StringComparison.OrdinalIgnoreCase))
            s = @"HKU\" + s[@"HKEY_USERS\".Length..];

        s = s.Replace(@"\-ContextMenuHandlers\", @"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase)
             .Replace(@"\-DragDropHandlers\", @"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase);

        int lastSlash = s.LastIndexOf('\\');
        if (lastSlash >= 0 && lastSlash < s.Length - 1)
        {
            s = s[..(lastSlash + 1)] + s[(lastSlash + 1)..].TrimStart('-');
        }
        return s;
    }

    private static string TryReadExistingProvenance(SqliteConnection conn, SqliteTransaction? tx, string locationKey)
    {
        try
        {
            string canonical = CanonicalizeLocationForStorage(locationKey);
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT SourceProcess FROM ItemProvenance WHERE LOWER(LocationKey) = LOWER($loc) LIMIT 1;";
            cmd.Parameters.AddWithValue("$loc", canonical);
            string? found = cmd.ExecuteScalar()?.ToString();
            if (!string.IsNullOrWhiteSpace(found))
                return found;
        }
        catch { }
        return string.Empty;
    }

    public string GetItemProvenance(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return string.Empty;

        try
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            string found = TryReadExistingProvenance(conn, null, locationKey);
            if (!string.IsNullOrWhiteSpace(found))
                return found;

            var variants = ExpandLocationMatchVariants(locationKey);
            if (variants.Count == 0)
                return string.Empty;

            using var cmd = conn.CreateCommand();
            var paramNames = new List<string>(variants.Count);
            for (int i = 0; i < variants.Count; i++)
            {
                string pname = $"$v{i}";
                paramNames.Add($"LOWER({pname})");
                cmd.Parameters.AddWithValue(pname, variants[i]);
            }
            cmd.CommandText = $"""
                SELECT SourceProcess FROM AuditLogs
                WHERE LOWER(TargetLocation) IN ({string.Join(", ", paramNames)})
                  AND SourceProcess IS NOT NULL AND SourceProcess <> ''
                ORDER BY LogId DESC
                LIMIT 1;
                """;
            return cmd.ExecuteScalar()?.ToString() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// 将指定位置（及其禁用状态变体）对应的“待审核/暂存”日志状态核销更新，避免重复出现或卸载后残留计数
    /// </summary>
    public void ResolvePendingAuditLogs(string locationKey, string resolvedActionLabel)
    {
        if (string.IsNullOrWhiteSpace(locationKey)) return;
        var variants = ExpandLocationMatchVariants(locationKey);
        if (variants.Count == 0) return;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        var paramNames = new List<string>(variants.Count);
        for (int i = 0; i < variants.Count; i++)
        {
            string pname = $"$v{i}";
            paramNames.Add($"LOWER({pname})");
            cmd.Parameters.AddWithValue(pname, variants[i]);
        }
        cmd.CommandText = $"""
            UPDATE AuditLogs
            SET ActionTaken = $resolved
            WHERE LOWER(TargetLocation) IN ({string.Join(", ", paramNames)})
              AND (ActionTaken LIKE '%待审%' OR ActionTaken LIKE '%暂存%' OR ActionTaken LIKE '%Pending Audit%');
            """;
        cmd.Parameters.AddWithValue("$resolved", resolvedActionLabel);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// 开源发行版本不再内置任何预置规则，规则库初始化保持完全为空（由用户自主审核生成）。
    /// </summary>
    public int SeedDefaultShowcaseRulesIfEmpty() => 0;

    public List<KnownBaselineRecord> LoadAllKnownBaselines()
    {
        var list = new List<KnownBaselineRecord>();
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT LocationKey, Category, TargetBinaryPath, NormalizedPath, RawState,
                       FileLastWriteUtcTicks, FileLength, FirstSeenUtc, LastSeenUtc
                FROM KnownBaselineItems;
                """;
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                DateTime.TryParse(
                    reader.IsDBNull(7) ? string.Empty : reader.GetString(7),
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind,
                    out var firstSeen);
                DateTime.TryParse(
                    reader.IsDBNull(8) ? string.Empty : reader.GetString(8),
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind,
                    out var lastSeen);

                list.Add(new KnownBaselineRecord
                {
                    LocationKey = reader.GetString(0),
                    Category = (MonitorCategory)reader.GetInt32(1),
                    TargetBinaryPath = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                    NormalizedPath = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                    RawState = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                    FileLastWriteUtcTicks = reader.IsDBNull(5) ? 0L : reader.GetInt64(5),
                    FileLength = reader.IsDBNull(6) ? 0L : reader.GetInt64(6),
                    FirstSeenUtc = firstSeen == default ? DateTime.UtcNow : firstSeen,
                    LastSeenUtc = lastSeen == default ? DateTime.UtcNow : lastSeen
                });
            }
        }
        catch { }
        return list;
    }

    public void UpsertKnownBaselinesBatch(IEnumerable<KnownBaselineRecord> records)
    {
        if (records == null)
            return;

        var items = records as ICollection<KnownBaselineRecord> ?? records.ToList();
        if (items.Count == 0)
            return;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO KnownBaselineItems
                (LocationKey, Category, TargetBinaryPath, NormalizedPath, RawState,
                 FileLastWriteUtcTicks, FileLength, FirstSeenUtc, LastSeenUtc)
            VALUES
                ($loc, $cat, $bin, $norm, $raw, $ticks, $len, $first, $last)
            ON CONFLICT(LocationKey) DO UPDATE SET
                Category = excluded.Category,
                TargetBinaryPath = excluded.TargetBinaryPath,
                NormalizedPath = excluded.NormalizedPath,
                RawState = excluded.RawState,
                FileLastWriteUtcTicks = CASE WHEN excluded.FileLastWriteUtcTicks > 0 THEN excluded.FileLastWriteUtcTicks ELSE KnownBaselineItems.FileLastWriteUtcTicks END,
                FileLength = CASE WHEN excluded.FileLength > 0 THEN excluded.FileLength ELSE KnownBaselineItems.FileLength END,
                LastSeenUtc = excluded.LastSeenUtc;
            """;

        var pLoc = cmd.Parameters.Add("$loc", SqliteType.Text);
        var pCat = cmd.Parameters.Add("$cat", SqliteType.Integer);
        var pBin = cmd.Parameters.Add("$bin", SqliteType.Text);
        var pNorm = cmd.Parameters.Add("$norm", SqliteType.Text);
        var pRaw = cmd.Parameters.Add("$raw", SqliteType.Text);
        var pTicks = cmd.Parameters.Add("$ticks", SqliteType.Integer);
        var pLen = cmd.Parameters.Add("$len", SqliteType.Integer);
        var pFirst = cmd.Parameters.Add("$first", SqliteType.Text);
        var pLast = cmd.Parameters.Add("$last", SqliteType.Text);

        foreach (var rec in items)
        {
            if (string.IsNullOrWhiteSpace(rec.LocationKey))
                continue;
            pLoc.Value = rec.LocationKey.Trim();
            pCat.Value = (int)rec.Category;
            pBin.Value = rec.TargetBinaryPath ?? string.Empty;
            pNorm.Value = rec.NormalizedPath ?? string.Empty;
            pRaw.Value = rec.RawState ?? string.Empty;
            pTicks.Value = rec.FileLastWriteUtcTicks;
            pLen.Value = rec.FileLength;
            pFirst.Value = rec.FirstSeenUtc.ToUniversalTime().ToString("O");
            pLast.Value = rec.LastSeenUtc.ToUniversalTime().ToString("O");
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    public int RemoveKnownBaselinesBatch(IEnumerable<string> locationKeys)
    {
        if (locationKeys == null)
            return 0;

        var list = locationKeys.Where(k => !string.IsNullOrWhiteSpace(k)).ToList();
        if (list.Count == 0)
            return 0;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "DELETE FROM KnownBaselineItems WHERE LOWER(LocationKey) = LOWER($loc);";
        var pLoc = cmd.Parameters.Add("$loc", SqliteType.Text);
        int affected = 0;
        foreach (string key in list)
        {
            pLoc.Value = key.Trim();
            affected += cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return affected;
    }

    public void RemoveKnownBaseline(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;
        RemoveKnownBaselinesBatch(ExpandLocationMatchVariants(locationKey));
    }

    public void Dispose()
    {
        using var conn = new SqliteConnection(_connectionString);
        SqliteConnection.ClearPool(conn);
    }
}

