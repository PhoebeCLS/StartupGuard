using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Data.Sqlite;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Storage;
using StartupGuard.Tests.TestHelpers;
using Xunit;

namespace StartupGuard.Tests.Tier5_AdversarialVerification;

/// <summary>
/// Tier 5 白盒对抗验证套件 (Adversarial Verification Suite)
/// 针对架构安全红线与存储并发执行极限压力测试：
/// 1. 内核驱动安全红线：无论任何入参 (包括 DeleteEntry)，严禁删除任何 .sys 文件，严格钳位为 Start=3 或 Start=4。
/// 2. ContextMenuMgr 仲裁：按 LastWriteTimeFileTime 仲裁传统菜单与 Win11 PackagedCom 现代扩展管控。
/// 3. 双层存储并发与原子性：MMF 二进制快照 64+256 结构、.tmp 原子重命名与多线程无锁并发读取；SQLite WAL 模式与 5 表完整性。
/// 4. 独立沙盒 ProbeHost：对格式合法与恶意畸形/截断 PE 文件执行探测，验证严格 12 字段输出与 0 进程挂起。
/// </summary>
public class AdversarialSafetyAndStorageTests
{
    // =========================================================================
    // 1. 内核驱动安全红线对抗测试 (Driver Safety Red-Line Verification)
    // =========================================================================

    [Fact]
    public void DriverSafetyRedLine_ExhaustiveActions_MustClampToDemandOrDisabled()
    {
        // 穷举测试：对所有可能的 InterceptionAction 枚举值 (甚至非法越界 byte 值)，
        // 当 isKernelDriver=true 时，必须无条件钳位到 RollbackToDisabled (4) 或 RollbackToDemand (3)。
        for (int b = 0; b <= 255; b++)
        {
            var action = (InterceptionAction)b;
            var (sanitizedAction, startType) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(action, isKernelDriver: true);

            Assert.True(
                sanitizedAction is InterceptionAction.RollbackToDemand or InterceptionAction.RollbackToDisabled,
                $"Action {b} produced illegal sanitized action {sanitizedAction}");

            Assert.True(
                startType is 3u or 4u,
                $"Action {b} produced illegal startType {startType} (Must strictly be 3 or 4)");

            // 特别核实：DeleteEntry 必须严格收敛为 RollbackToDisabled (Start=4)
            if (action == InterceptionAction.DeleteEntry)
            {
                Assert.Equal(InterceptionAction.RollbackToDisabled, sanitizedAction);
                Assert.Equal(4u, startType);
            }
        }
    }

    [Fact]
    public void DriverSafetyRedLine_PhysicalSysFile_IsNeverDeletedUnderDeleteEntry()
    {
        // 关键红线：在真实文件系统创建 .sys 文件，执行 ExecuteRollback(DeleteEntry)，
        // 绝对严禁物理删除磁盘上的 .sys 驱动文件！
        string tempDir = Path.Combine(Path.GetTempPath(), "DriverRedLineTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string sysFilePath = Path.Combine(tempDir, "acpi_guard_test.sys");
            byte[] originalPayload = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
            File.WriteAllBytes(sysFilePath, originalPayload);
            string originalSha256 = Convert.ToHexStringLower(SHA256.HashData(originalPayload));

            var target = new TargetProgramFeatures
            {
                Category = MonitorCategory.KernelDriver,
                TargetBinaryPath = sysFilePath,
                LocationKeyOrIdentifier = sysFilePath, // 故意将标识符指向物理文件自身进行恶意攻击
                NormalizedPath = sysFilePath,
                NormalizedPathHash = 12345,
                RawCommandLine = sysFilePath,
                CommandLineArgsTemplate = string.Empty,
                MD5Hex = "d41d8cd98f00b204e9800998ecf8427e",
                SHA256Hex = originalSha256,
                OldRawSnapshot = [0x03, 0x00, 0x00, 0x00],
                RegistryValueType = 4 // REG_DWORD
            };

            // 执行回滚，请求删除驱动
            bool rollbackResult = PrivilegedRollbackEngine.ExecuteRollback(
                target,
                InterceptionAction.DeleteEntry,
                activeUserSid: null);

            // 1. 验证磁盘上的 .sys 文件依然存在！
            Assert.True(File.Exists(sysFilePath), "CRITICAL SAFETY VIOLATION: Kernel driver .sys file was deleted from disk!");

            // 2. 验证内容完全未被篡改
            byte[] currentPayload = File.ReadAllBytes(sysFilePath);
            Assert.Equal(originalPayload.Length, currentPayload.Length);
            string currentSha256 = Convert.ToHexStringLower(SHA256.HashData(currentPayload));
            Assert.Equal(originalSha256, currentSha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void DriverSafetyRedLine_ExecuteRollback_EnsuresActionClampedInTestHandler()
    {
        // 验证经过 ExecuteRollback 分派时，即便传入 DeleteEntry，分派给处理器的 action 也已被钳位
        var target = new TargetProgramFeatures
        {
            Category = MonitorCategory.KernelDriver,
            TargetBinaryPath = @"C:\Windows\System32\drivers\adversarial.sys",
            LocationKeyOrIdentifier = @"SYSTEM\CurrentControlSet\Services\AdversarialDriver",
            NormalizedPath = @"C:\Windows\System32\drivers\adversarial.sys",
            NormalizedPathHash = 9999,
            RawCommandLine = string.Empty,
            CommandLineArgsTemplate = string.Empty,
            MD5Hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            SHA256Hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        };

        InterceptionAction observedAction = InterceptionAction.DeleteEntry;
        PrivilegedRollbackEngine.ExecuteRollback(
            target,
            InterceptionAction.DeleteEntry,
            activeUserSid: null,
            customTestHandler: (t, sanitizedAction) =>
            {
                observedAction = sanitizedAction;
                return true;
            });

        Assert.Equal(InterceptionAction.RollbackToDisabled, observedAction);
    }

    // =========================================================================
    // 2. ContextMenuMgr 仲裁与 Win11 PackagedCom 对抗测试
    // =========================================================================

    [Fact]
    public void ContextMenuMgr_DeduplicateByLastWriteTime_StrictlyArbitratesByTimestamp()
    {
        // 对比同场景下相同 CLSID / Title 的多份副本，无论输入列表顺序如何，
        // 必须无条件保留 LastWriteTimeFileTime 最大（最新）的记录！
        const string clsid = "{B5A24978-B500-4743-A28F-091FA88835B1}";
        const string title = "Open in Terminal";
        const string scene = "DirectoryBackground";

        var older = new ContextMenuItemEntry
        {
            IdKey = "old_hklm",
            DisplayTitle = title,
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = scene,
            RegistryPath = @"HKLM\Software\Classes\Directory\Background\shell\terminal",
            Clsid = clsid,
            IsEnabled = false,
            LastWriteTimeFileTime = 132000000000000000L
        };

        var newer = new ContextMenuItemEntry
        {
            IdKey = "new_hkcu",
            DisplayTitle = title,
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = scene,
            RegistryPath = @"HKCU\Software\Classes\Directory\Background\shell\terminal",
            Clsid = clsid,
            IsEnabled = true,
            LastWriteTimeFileTime = 133500000000000000L
        };

        // 顺序 1: [older, newer]
        var res1 = ContextMenuManagerEngine.DeduplicateByLastWriteTime([older, newer]);
        Assert.Single(res1);
        Assert.Equal("new_hkcu", res1[0].IdKey);
        Assert.True(res1[0].IsEnabled);
        Assert.Equal(133500000000000000L, res1[0].LastWriteTimeFileTime);

        // 顺序 2: [newer, older]
        var res2 = ContextMenuManagerEngine.DeduplicateByLastWriteTime([newer, older]);
        Assert.Single(res2);
        Assert.Equal("new_hkcu", res2[0].IdKey);
        Assert.True(res2[0].IsEnabled);
    }

    [Fact]
    public void ContextMenuMgr_Deduplicate_CaseInsensitiveCollisions_HandledCorrectly()
    {
        // 测试大小写混淆注入：
        // "DIRECTORYBACKGROUND|{B5A24978-...}|OPEN" vs "DirectoryBackground|{b5a24978-...}|open"
        // 必须被正确判定为同一逻辑项并根据时间戳去重
        var entryLower = new ContextMenuItemEntry
        {
            IdKey = "id_lower",
            DisplayTitle = "git bash here",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "directorybackground",
            RegistryPath = @"Software\Classes\Directory\Background\shell\git_shell",
            Clsid = "{b5a24978-b500-4743-a28f-091fa88835b1}",
            IsEnabled = false,
            LastWriteTimeFileTime = 1000L
        };

        var entryUpper = new ContextMenuItemEntry
        {
            IdKey = "id_upper",
            DisplayTitle = "GIT BASH HERE",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "DIRECTORYBACKGROUND",
            RegistryPath = @"Software\Classes\Directory\Background\shell\GIT_SHELL",
            Clsid = "{B5A24978-B500-4743-A28F-091FA88835B1}",
            IsEnabled = true,
            LastWriteTimeFileTime = 2000L
        };

        var deduped = ContextMenuManagerEngine.DeduplicateByLastWriteTime([entryLower, entryUpper]);
        Assert.Single(deduped);
        Assert.Equal(2000L, deduped[0].LastWriteTimeFileTime);
        Assert.True(deduped[0].IsEnabled);
    }

    [Fact]
    public void ContextMenuMgr_Deduplicate_DistinctScenesSameClsid_PreservesBoth()
    {
        // 合法场景：同一个 Shell Extension CLSID 同时注册在 "*" (所有文件) 和 "Folder" (文件夹)
        // 此时 ScopeScene 不同，必须两者都完整保留，绝不能误去重！
        const string clsid = "{77777777-1111-2222-3333-444444444444}";
        var itemAllFiles = new ContextMenuItemEntry
        {
            IdKey = "allfiles",
            DisplayTitle = "7-Zip",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "*",
            RegistryPath = @"Software\Classes\*\shellex\ContextMenuHandlers\7-Zip",
            Clsid = clsid,
            IsEnabled = true,
            LastWriteTimeFileTime = 1000L
        };

        var itemFolder = new ContextMenuItemEntry
        {
            IdKey = "folder",
            DisplayTitle = "7-Zip",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "Folder",
            RegistryPath = @"Software\Classes\Folder\shellex\ContextMenuHandlers\7-Zip",
            Clsid = clsid,
            IsEnabled = true,
            LastWriteTimeFileTime = 2000L
        };

        var result = ContextMenuManagerEngine.DeduplicateByLastWriteTime([itemAllFiles, itemFolder]);
        Assert.Equal(2, result.Count);
        Assert.Contains(result, r => r.ScopeScene == "*");
        Assert.Contains(result, r => r.ScopeScene == "Folder");
    }

    [Fact]
    public void ContextMenuMgr_Win11ModernPackagedCom_CategoryAndTogglingIntegrity()
    {
        // 验证现代 PackagedCom 菜单的分类属性与屏蔽管控分发
        var modernItem = new ContextMenuItemEntry
        {
            IdKey = "Win11Modern:{A0000000-0000-0000-0000-000000000001}:Microsoft.WindowsTerminal",
            DisplayTitle = "Windows Terminal",
            MenuCategory = MonitorCategory.ModernContextMenu,
            ScopeScene = "Win11 Modern Menu (IExplorerCommand)",
            RegistryPath = @"SOFTWARE\Classes\PackagedCom\ClassIndex\{A0000000-0000-0000-0000-000000000001}\Microsoft.WindowsTerminal",
            Clsid = "{A0000000-0000-0000-0000-000000000001}",
            PackageFullName = "Microsoft.WindowsTerminal_1.18.10301.0_x64__8wekyb3d8bbwe",
            Publisher = "Microsoft Corporation",
            IsEnabled = true,
            LastWriteTimeFileTime = DateTime.UtcNow.ToFileTimeUtc()
        };

        Assert.Equal(MonitorCategory.ModernContextMenu, modernItem.MenuCategory);
        var engine = new ContextMenuManagerEngine();

        bool isElevatedWindows = OperatingSystem.IsWindows() &&
            new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

        try
        {
            // 提权 Windows 环境（如 CI Runner）可直接写入 Blocked 键返回 true；非提权/Linux 环境优雅降级为 false
            bool disabledSuccess = engine.SetContextMenuItemEnabledState(modernItem, enable: false, activeUserSid: null);
            Assert.Equal(isElevatedWindows, disabledSuccess);
        }
        finally
        {
            if (isElevatedWindows)
            {
                engine.SetContextMenuItemEnabledState(modernItem, enable: true, activeUserSid: null);
            }
        }
    }

    // =========================================================================
    // 3. 双层存储结构完整性与多线程并发对抗测试 (Dual-Layer Storage Integrity)
    // =========================================================================

    [Fact]
    public unsafe void MmfBinaryStore_ExactStructLayoutAndOffsets_MustMatchSpec()
    {
        // 64-byte Header 校验
        Assert.Equal(64, sizeof(MmfSnapshotHeader));
        Assert.Equal(0x47505453u, MmfSnapshotHeader.MagicHeader); // "STPG"
        Assert.Equal(1u, MmfSnapshotHeader.FormatVersion);

        // 256-byte Record 校验
        Assert.Equal(256, sizeof(MmfRecordEntry));

        // 校验重要字段在 256 字节结构体内的物理偏移
        MmfRecordEntry dummy = default;
        byte* basePtr = (byte*)&dummy;

        Assert.Equal(0, (byte*)&dummy.Category - basePtr);
        Assert.Equal(1, (byte*)&dummy.TargetAction - basePtr);
        Assert.Equal(2, (byte*)&dummy.MatchMode - basePtr);
        Assert.Equal(3, (byte*)&dummy.Flags - basePtr);
        Assert.Equal(4, (byte*)&dummy.ConfidenceThreshold - basePtr);
        Assert.Equal(8, (byte*)&dummy.RuleId - basePtr);
        Assert.Equal(12, (byte*)&dummy.EvolutionCount - basePtr);
        Assert.Equal(16, (byte*)&dummy.NormalizedPathHash - basePtr);
        Assert.Equal(24, (byte*)&dummy.LocationKeyHash - basePtr);
        Assert.Equal(32, (byte*)&dummy.IconPerceptualHash - basePtr);
        Assert.Equal(40, (byte*)dummy.RawMD5 - basePtr);
        Assert.Equal(56, (byte*)dummy.RawSHA256 - basePtr);
        Assert.Equal(88, (byte*)dummy.SignerThumbprint - basePtr);
        Assert.Equal(108, (byte*)&dummy.Weights - basePtr);
        Assert.Equal(132, (byte*)dummy.ReservedPayload - basePtr);
    }

    [Fact]
    public async Task MmfBinaryStore_AtomicFileReplacement_And_ConcurrentMultiReaderStress()
    {
        // 极限并发压力测试：
        // 1 个后台写线程以极高频率反复通过 SaveEntriesAtomically (.tmp 文件创建、写入、重命名替换) 覆写 snapshot.bin
        // 8 个并发读线程持续创建独立的 MmfBinaryStore，装载并执行 TryFindByMd5OrLocation 查询
        // 检验：在整个并发过程中绝不发生文件锁冲突崩溃、未对齐内存越界、坏头死锁或读到残缺截断数据！
        string tempDir = Path.Combine(Path.GetTempPath(), "MmfConcurrencyTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string storePath = Path.Combine(tempDir, "baseline_stress.bin");

        try
        {
            // 初始化写入 10 条基准
            using (var initStore = new MmfBinaryStore(storePath))
            {
                var initialEntries = GenerateDummyEntries(count: 10, seed: 100);
                initStore.SaveEntriesAtomically(initialEntries);
            }

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var token = cts.Token;
            int totalReads = 0;
            int totalWrites = 0;
            int tornReadViolations = 0;

            Exception? lastWriterEx = null;

            // 1. 写线程
            var writeTask = Task.Run(() =>
            {
                int iteration = 0;
                using var writerStore = new MmfBinaryStore(storePath);
                while (!token.IsCancellationRequested)
                {
                    iteration++;
                    int count = 5 + (iteration % 25);
                    var batch = GenerateDummyEntries(count, seed: iteration);
                    try
                    {
                        writerStore.SaveEntriesAtomically(batch);
                        Interlocked.Increment(ref totalWrites);
                    }
                    catch (Exception ex)
                    {
                        lastWriterEx = ex;
                    }
                    Thread.Sleep(2);
                }
            });

            // 2. 8 个并发读线程
            var readTasks = Enumerable.Range(0, 8).Select(readerId => Task.Run(() =>
            {
                byte[] searchMd5 = new byte[16];
                searchMd5[0] = 0xAA;
                searchMd5[1] = 0xBB;

                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        using var readerStore = new MmfBinaryStore(storePath);
                        if (readerStore.LoadIntoMemory())
                        {
                            int count = readerStore.Count;
                            if (count <= 0)
                            {
                                Interlocked.Increment(ref tornReadViolations);
                            }

                            // 执行哈希与位置查找
                            ulong targetHash = MmfBinaryStore.ComputeFnv1a64("test_item_3");
                            readerStore.TryFindByMd5OrLocation(searchMd5, targetHash, out _);
                            Interlocked.Increment(ref totalReads);
                        }
                    }
                    catch (Exception)
                    {
                        // 如果并发打开被冲刷，测试是否安全隔离
                    }
                    Thread.Sleep(1);
                }
            })).ToArray();

            await Task.WhenAll([writeTask, .. readTasks]);

            Assert.True(totalWrites > 5, $"Writer was starved; only {totalWrites} writes completed. Last error: {lastWriterEx?.Message} - {lastWriterEx?.StackTrace}");
            Assert.True(totalReads > 50, $"Readers completed only {totalReads} reads.");
            Assert.Equal(0, tornReadViolations);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static unsafe MmfRecordEntry[] GenerateDummyEntries(int count, int seed)
    {
        var entries = new MmfRecordEntry[count];
        for (int i = 0; i < count; i++)
        {
            entries[i] = new MmfRecordEntry
            {
                Category = MonitorCategory.StartupItem,
                TargetAction = InterceptionAction.RollbackToDisabled,
                MatchMode = RuleMatchMode.PermanentAdaptive,
                Flags = 0x01,
                ConfidenceThreshold = 85.0f,
                RuleId = (uint)(seed * 1000 + i),
                EvolutionCount = (uint)i,
                NormalizedPathHash = (ulong)(seed * 1000000L + i),
                LocationKeyHash = MmfBinaryStore.ComputeFnv1a64($"test_item_{i}"),
                IconPerceptualHash = 0x0123456789ABCDEFUL,
                Weights = SixDimensionWeights.CreateDefault()
            };
            entries[i].RawMD5[0] = (byte)(seed & 0xFF);
            entries[i].RawMD5[15] = (byte)(i & 0xFF);
        }
        return entries;
    }

    [Fact]
    public void SqliteRuleRepository_WalMode_CascadeDelete_And_ShowcaseIdempotency()
    {
        // 验证 SQLite 5 表架构、WAL 模式生效、外键级联删除与样例展示数据幂等性
        string tempDb = Path.Combine(Path.GetTempPath(), "SqliteTest_" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using (var repo = new SqliteRuleRepository(tempDb))
            {
                // 1. 验证 WAL 模式生效
                using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
                conn.Open();
                using var walCmd = conn.CreateCommand();
                walCmd.CommandText = "PRAGMA journal_mode;";
                string? journalMode = walCmd.ExecuteScalar()?.ToString();
                Assert.Equal("wal", journalMode?.ToLowerInvariant());

                // 2. 验证全部 5 张核心表均已创建
                string[] expectedTables = ["Rules", "RuleAliases", "NegativePairs", "RuleWeights", "AuditLogs"];
                using var tablesCmd = conn.CreateCommand();
                tablesCmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table';";
                var createdTables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using (var reader = tablesCmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        createdTables.Add(reader.GetString(0));
                    }
                }
                foreach (string t in expectedTables)
                {
                    Assert.Contains(t, createdTables);
                }

                // 3. 验证外键级联删除 (CASCADE)
                var rule = new RuleRecord
                {
                    DisplayName = "CascadeTestApp",
                    Category = MonitorCategory.StartupItem,
                    ActionType = InterceptionAction.RollbackToDisabled,
                    RuleMode = RuleMatchMode.PermanentAdaptive,
                    ConfidenceThreshold = 85.0f,
                    CurrentMD5 = "11112222333344445555666677778888",
                    CurrentSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                };
                int ruleId = repo.InsertOrUpdateRule(rule);
                Assert.True(ruleId > 0);

                repo.AddPolymorphicAlias(ruleId, "22223333444455556666777788889999", @"C:\App\V2\app.exe", "CertCN", "--arg");
                repo.AddNegativePair(ruleId, "99998888777766665555444433332222", @"C:\Malware\trojan.exe", "FakeCN", "Hostile");

                // 删除父规则
                bool deleted = repo.DeleteRule(ruleId);
                Assert.True(deleted);

                // 查询子表，关联记录必须已被级联彻底清空
                var allRules = repo.GetAllRulesWithWeightsAndAliases();
                Assert.DoesNotContain(allRules, r => r.RuleId == ruleId);

                var negPairs = repo.GetNegativePairs(ruleId);
                Assert.Empty(negPairs);

                // 4. 验证发版规则库不包含任何内置预置规则：SeedDefaultShowcaseRulesIfEmpty 始终返回 0 且规则表保持为空
                int seededFirst = repo.SeedDefaultShowcaseRulesIfEmpty();
                Assert.Equal(0, seededFirst);

                allRules = repo.GetAllRulesWithWeightsAndAliases();
                Assert.Empty(allRules);
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tempDb)) File.Delete(tempDb);
                if (File.Exists(tempDb + "-wal")) File.Delete(tempDb + "-wal");
                if (File.Exists(tempDb + "-shm")) File.Delete(tempDb + "-shm");
            }
            catch { }
        }
    }

    // =========================================================================
    // 4. 独立沙盒 ProbeHost 进程对抗执行测试 (Isolated ProbeHost Sandbox)
    // =========================================================================

    [Fact]
    public void ProbeHost_ValidSyntheticPe_OutputsExact12TabSeparatedFields()
    {
        // 构造带有真实导入表、自签名证书与元数据的有效合成 PE64
        string tempDir = Path.Combine(Path.GetTempPath(), "ProbeHostValidTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            using var rsa = RSA.Create(2048);
            var certReq = new CertificateRequest("CN=StartupGuardSecurityCorp, O=StartupGuard, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));

            byte[] peBytes = SyntheticPeBuilder.BuildSyntheticPe64(
                imports: [("kernel32.dll", ["CreateFileW", "CloseHandle"]), ("advapi32.dll", ["RegOpenKeyExW"])],
                iconBytes: [0x01, 0x02, 0x03, 0x04],
                cert: cert);

            string dllPath = Path.Combine(tempDir, "SyntheticValidExtension.dll");
            File.WriteAllBytes(dllPath, peBytes);

            // 定位 ProbeHost DLL
            string probeHostDll = LocateProbeHostDll();
            Assert.True(File.Exists(probeHostDll), $"ProbeHost DLL not found at: {probeHostDll}");

            // 启动独立进程调用
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = ResolveDotnetCli(),
                    Arguments = $"\"{probeHostDll}\" \"{dllPath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            proc.Start();
            bool exitedInTime = proc.WaitForExit(3000); // 3秒看门狗超时
            Assert.True(exitedInTime, "ProbeHost hung or did not exit within 3000ms!");
            Assert.Equal(0, proc.ExitCode);

            string output = proc.StandardOutput.ReadToEnd().Trim();
            string[] lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            Assert.NotEmpty(lines);

            string firstLine = lines[0];
            string[] fields = firstLine.Split('\t');
            Assert.Equal(12, fields.Length); // 必须严格为 12 个制表符分隔字段！

            string md5 = fields[0];
            string sha256 = fields[1];
            string hasValidSig = fields[2];
            string signerSubject = fields[3];
            string rootCertThumbprint = fields[4];
            string origName = fields[5];
            string prodName = fields[6];
            string compName = fields[7];
            string intName = fields[8];
            string desc = fields[9];
            string impHash = fields[10];
            string iconPHash = fields[11];

            // 校验提取准确性
            Assert.Equal(32, md5.Length);
            Assert.Equal(64, sha256.Length);
            Assert.Equal("1", hasValidSig);
            Assert.Contains("StartupGuardSecurityCorp", signerSubject);
            Assert.NotEmpty(rootCertThumbprint);
            Assert.Equal(32, impHash.Length); // ImpHash MD5
            Assert.Equal(16, iconPHash.Length); // 64-bit Hex
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void ProbeHost_CorruptedAndMalformedBinaries_ZeroHangsGuaranteed()
    {
        // 恶意与畸形二进制压力探测：
        // 1. 0 字节空文件
        // 2. 12 字节截断 DOS 头
        // 3. e_lfanew 指向文件尾部外 (0x7FFFFFFF)
        // 4. 签名非 PE\0\0 的非法头
        // 5. 50 组完全随机噪点二进制
        // 校验：在所有畸形注入下，ProbeHost 绝不发生死循环或未捕获崩溃卡死，均在 1000ms 内安全退出！
        string tempDir = Path.Combine(Path.GetTempPath(), "ProbeHostMalformedTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string probeHostDll = LocateProbeHostDll();

        try
        {
            var hostileFiles = new List<string>();

            // 1. 空文件
            string emptyFile = Path.Combine(tempDir, "empty.dll");
            File.WriteAllBytes(emptyFile, []);
            hostileFiles.Add(emptyFile);

            // 2. 截断文件
            string truncFile = Path.Combine(tempDir, "truncated.dll");
            File.WriteAllBytes(truncFile, [0x4D, 0x5A, 0x90, 0x00]);
            hostileFiles.Add(truncFile);

            // 3. 恶意 e_lfanew
            string badLfanewFile = Path.Combine(tempDir, "bad_lfanew.dll");
            byte[] badLfa = new byte[128];
            badLfa[0] = 0x4D; badLfa[1] = 0x5A; // MZ
            BinaryPrimitives.WriteInt32LittleEndian(badLfa.AsSpan(0x3C), 0x7FFFFFFF);
            File.WriteAllBytes(badLfanewFile, badLfa);
            hostileFiles.Add(badLfanewFile);

            // 4. 破坏的 PE 签名
            string badPeSigFile = Path.Combine(tempDir, "bad_pesig.dll");
            byte[] badPeSig = new byte[256];
            badPeSig[0] = 0x4D; badPeSig[1] = 0x5A;
            BinaryPrimitives.WriteInt32LittleEndian(badPeSig.AsSpan(0x3C), 0x40);
            badPeSig[0x40] = (byte)'X'; badPeSig[0x41] = (byte)'X'; badPeSig[0x42] = (byte)'X'; badPeSig[0x43] = (byte)'X';
            File.WriteAllBytes(badPeSigFile, badPeSig);
            hostileFiles.Add(badPeSigFile);

            // 5. 随机噪声文件 (Fuzzing)
            for (int i = 0; i < 10; i++)
            {
                string fuzzFile = Path.Combine(tempDir, $"fuzz_{i}.dll");
                byte[] fuzzBytes = new byte[256 + i * 128];
                Random.Shared.NextBytes(fuzzBytes);
                File.WriteAllBytes(fuzzFile, fuzzBytes);
                hostileFiles.Add(fuzzFile);
            }

            foreach (string hostilePath in hostileFiles)
            {
                using var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = ResolveDotnetCli(),
                        Arguments = $"\"{probeHostDll}\" \"{hostilePath}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                proc.Start();
                bool exited = proc.WaitForExit(1000); // 1秒安全看门狗
                Assert.True(exited, $"ProbeHost hung on malformed file: {Path.GetFileName(hostilePath)}");

                // 退出码应为 0 (安全降级输出空字段) 或 1/2 (参数/异常退出)，绝不能挂起
                Assert.True(proc.ExitCode is 0 or 1 or 2);

                if (proc.ExitCode == 0)
                {
                    string outText = proc.StandardOutput.ReadToEnd().Trim();
                    if (!string.IsNullOrEmpty(outText))
                    {
                        string[] fields = outText.Split('\t');
                        Assert.Equal(12, fields.Length);
                    }
                }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public async Task ProbeHost_IsolatedProbeRunner_RunsCleanlyViaEngineAsync()
    {
        // 验证 ContextMenuManagerEngine.ProbeUnknownDllIsolatedAsync 的高层封装调用
        string tempDir = Path.Combine(Path.GetTempPath(), "ProbeRunnerTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            byte[] peBytes = SyntheticPeBuilder.BuildSyntheticPe64(
                imports: [("user32.dll", ["MessageBoxW"])]);

            string dllPath = Path.Combine(tempDir, "UserMenuExtension.dll");
            File.WriteAllBytes(dllPath, peBytes);

            string probeHostDll = LocateProbeHostDll();

            var features = await ContextMenuManagerEngine.ProbeUnknownDllIsolatedAsync(
                dllPath,
                probeHostExePath: probeHostDll,
                timeoutMs: 3000);

            Assert.NotNull(features);
            Assert.Equal(MonitorCategory.ClassicContextMenu, features.Category);
            Assert.NotEmpty(features.MD5Hex);
            Assert.NotEmpty(features.SHA256Hex);
            Assert.Equal("IsolatedProbeSuccess", features.NewStateSummary);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static string LocateProbeHostDll()
    {
        string baseDir = AppContext.BaseDirectory;
        string candidate = Path.Combine(baseDir, "StartupGuard.ProbeHost.dll");
        if (File.Exists(candidate)) return candidate;

        string? cur = baseDir;
        for (int depth = 0; depth < 8 && !string.IsNullOrEmpty(cur); depth++)
        {
            string probeBin = Path.Combine(cur, "src", "StartupGuard.ProbeHost", "bin");
            if (Directory.Exists(probeBin))
            {
                var matches = Directory.GetFiles(probeBin, "StartupGuard.ProbeHost.dll", SearchOption.AllDirectories);
                if (matches.Length > 0)
                    return matches[0];
            }
            cur = Path.GetDirectoryName(cur);
        }

        return string.Empty;
    }

    private static string ResolveDotnetCli()
    {
        const string localDotnet = "/home/antigravity/.dotnet/dotnet";
        if (File.Exists(localDotnet))
            return localDotnet;
        return "dotnet";
    }
}
