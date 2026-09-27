# IPAInspect

运行在 **iOS 设备本地**的离线 IPA 静态分析工具，侧载即用，不依赖任何云端服务，保护样本隐私。

> IPAInspect: On-device offline IPA static analyzer. Sideload on iOS to inspect plist, Mach-O, permissions and hardcoded URLs, detect privacy risks and malicious indicators.

## 功能特性

- **包结构与 Plist 解析**：读取 IPA 目录树，提取 Bundle ID、版本、最低系统、URL Scheme、ATS 配置、后台模式等信息
- **隐私权限审计**：扫描 iOS 隐私权限清单，标记高危权限（相机 / 相册 / 麦克风 / 定位 / 通讯录等）并给出风险说明
- **Mach-O 二进制分析**：架构、文件类型、平台、段节信息、加载命令、FairPlay 加密状态、代码签名槽、依赖动态库
- **字符串 / URL 提取**：扫描二进制内硬编码字符串，自动识别并分类 URL、IP、域名、邮箱、密钥等敏感信息，支持检索
- **风险检测引擎**：识别过度申请隐私权限、明文 HTTP 通信、内网 / 可疑服务器地址等恶意特征，自动评分并分级（安全 / 低风险 / 可疑 / 恶意软件），可识别裸聊勒索类恶意样本
- **可视化统计**：权限分布环形图、风险评分条、分级条形图
- **报告导出**：一键分享 Markdown / JSON 审计报告
- **本地样本库**：历史分析结果保存与检索

## 版本历史

| 版本 | 说明 | 状态 |
| --- | --- | --- |
| v1.0.0 | 首个可侧载版本：完整 IPA 静态分析引擎 + UIKit 界面 | ✅ 已发布 |

> 后续修复（如结果页布局、Mach-O 解析健壮性）会以递增版本号发布，详见 Releases。

## 使用引导

详见 [USAGE_GUIDE.md](USAGE_GUIDE.md)（侧载安装、导入分析、结果阅读、源码构建）。

## 免责声明

详见 [DISCLAIMER.md](DISCLAIMER.md)。本项目**仅用于合法的应用安全研究与学习**，禁止用于逆向破解、恶意软件分析、未经授权的商业审计。

## 从源码构建

在 Linux 上交叉编译产出未签名裸 IPA（参考 `build.sh`），需要：

- Swift 5.8 工具链（含 `ld64.lld`）
- iOS 16.4 SDK
- `ldid`（ad-hoc 签名）

```bash
./build.sh
# 产物：build-linux/IPAAnalyzer-<version>-raw-unsigned.ipa
```

## License

仅供学习研究使用，见 [DISCLAIMER.md](DISCLAIMER.md) 的条款约束。
