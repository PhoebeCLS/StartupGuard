# Third-Party Notices & Acknowledgements

`StartupGuard` is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
See [LICENSE](./LICENSE) for the full license text.

---

## 1. Special Acknowledgement & Inspiration

`StartupGuard` draws extensive architectural inspiration, Windows Registry / Shell Extension enumeration conventions, Win+X management logic, and right-click context menu design patterns from:

- **ContextMenuMgr (Context Menu Manager Plus)**
  - Repository: https://github.com/PLFJY/ContextMenuMgr
  - License: GNU General Public License v3.0 (GPL-3.0)

In keeping with `ContextMenuMgr`, we also gratefully acknowledge the projects credited in its `README.md`:

- **ContextMenuManager**
  - Repository: https://github.com/BluePointLilac/ContextMenuManager
  - License: GNU General Public License v3.0 (GPL-3.0)
- **Windows 11 Context Menu Manager**
  - Repository: https://github.com/branhill/windows-11-context-menu-manager
  - License: MIT License
- **UI.WPF.Modern**
  - Repository: https://github.com/iNKORE-NET/UI.WPF.Modern
  - Modern Fluent WPF control styles & themes reference

---

## 2. Direct Third-Party NuGet Dependencies

| Package | Version | Repository | License | Usage |
| :--- | :--- | :--- | :--- | :--- |
| **WPF-UI** | 4.3.0 | https://github.com/lepoco/wpfui | MIT | Fluent Design controls, Mica backdrop, dark/light theme engine |
| **Microsoft.Data.Sqlite** | 10.0.0 | https://github.com/dotnet/efcore | MIT | Local SQLite rule & audit log storage driver (SQLite core is Public Domain) |
| **xUnit / Microsoft.NET.Test.Sdk** | 2.9.3 / 17.14.1 | https://github.com/xunit/xunit | Apache-2.0 / MIT | Automated unit & regression test suite (dev/test only) |
