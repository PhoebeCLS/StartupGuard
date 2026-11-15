namespace StartupGuard.Core.Models;

/// <summary>
/// 6 大监控与拦截类别 (可在托盘菜单独立勾选)
/// </summary>
public enum MonitorCategory : byte
{
    StartupItem = 1,
    Win32Service = 2,
    KernelDriver = 3,
    ScheduledTask = 4,
    ClassicContextMenu = 5,
    ModernContextMenu = 6,
    WindowsPolicy = 7
}

/// <summary>
/// 拦截与回滚动作类型
/// </summary>
public enum InterceptionAction : byte
{
    /// <summary>放行并更新入基准</summary>
    Allow = 0,
    /// <summary>回滚为手动启动 (Demand = 3，驱动默认安全推荐)</summary>
    RollbackToDemand = 1,
    /// <summary>回滚为禁用状态 (Disabled = 4 / StartupApproved 禁用 / ShellEx Blocked)</summary>
    RollbackToDisabled = 2,
    /// <summary>直接删除注册项 (严禁用于删除驱动 .sys 物理文件)</summary>
    DeleteEntry = 3,
    /// <summary>还原到变更前原始字节快照</summary>
    RestorePreviousSnapshot = 4,
    /// <summary>回滚为延迟启动 (Start = 2, DelayedAutostart = 1)</summary>
    RollbackToDelayedAuto = 5,
    /// <summary>仅关闭弹窗不做任何系统或规则修改（仅记录日志供后续手动处置）</summary>
    DismissWithoutChange = 6
}

/// <summary>
/// 规则记忆模式
/// </summary>
public enum RuleMatchMode : byte
{
    /// <summary>模式一：仅当前版本严格 MD5 匹配</summary>
    StrictCurrentVersion = 0,
    /// <summary>模式二：永久自适应拦截 (六维可信度 + 多态演化)</summary>
    PermanentAdaptive = 1
}

/// <summary>
/// 系统研判风险等级
/// </summary>
public enum DiagnosticSeverity : byte
{
    /// <summary>常规新发现项</summary>
    NormalNew = 0,
    /// <summary>高概率同一软件版本正常迭代/目录迁移 (70 <= S < 85)</summary>
    LikelySameSoftware = 1,
    /// <summary>灰区存在较大特征偏离 (45 <= S < 70)</summary>
    SuspiciousDeviation = 2,
    /// <summary>红色高危警告：历史有签名但当前签名丢失，疑似被木马替换</summary>
    CriticalSignatureLost = 3
}

/// <summary>
/// 右键菜单拦截通知策略
/// </summary>
public enum ContextMenuInterceptionPolicy : byte
{
    /// <summary>立即弹窗询问</summary>
    PromptImmediately = 0,
    /// <summary>默认静默禁用隔离并放入待审核队列</summary>
    SilentQuarantineThenAudit = 1
}
