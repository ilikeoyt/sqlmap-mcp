# SQLMap MCP

**SQLMap MCP** 是一个基于 **FastMCP 框架** 的强大工具，专为集成 **SQLMap** 进行自动化 SQL 注入扫描而设计。它提供了两种不同的实现方式，支持异步扫描、实时监控和详细报告生成，帮助安全测试人员更高效地识别和分析 SQL 注入漏洞。

## 📌 功能亮点

- **异步扫描执行**：利用异步编程模型，在不阻塞主线程的情况下执行 SQLMap 扫描任务
- **实时进度监控**：通过 Server-Sent Events (SSE) 技术实时获取扫描进度和结果
- **任务管理系统**：支持创建、暂停、恢复和终止扫描任务，提供任务状态跟踪
- **智能结果解析**：自动解析 SQLMap 输出，提取关键信息并生成结构化报告
- **多环境支持**：兼容 Linux、Windows 和 macOS 系统

## 🚀 安装指南

### 环境要求

- Python 3.7+
- SQLMap (建议最新版本)

### 安装步骤

```bash
uv venv
source .venv/bin/activate

# 安装依赖
uv add "mcp[cli]" httpx
```

## 📖 使用教程

### 方法一：基于 SSE 的异步扫描

```bash
# 启动 SSE 服务器  
mcp run sqlmap_mcp_sse.py --transport sse
```

**❓ Agent接入**

cherry studio

![image-20250602213138905](D:\笔记\AWD.assets\image-20250602213138905.png)

### 方法二：基于标准输入输出的任务管理

```bash
# 启动任务管理服务器  
mcp run sqlmap_mcp_stdio.py
```

#### ❓ Agent接入（目前暂不支持cherry studio）

Cursor

![image-20250602213210479](D:\笔记\AWD.assets\image-20250602213210479.png)

## 📊 扫描结果示例

### 漏洞概览

![image-20250602212715377](D:\笔记\AWD.assets\image-20250602212715377.png)

## 📦 代码结构  

```
sqlmap-mcp/
├── sqlmap_mcp_sse.py # SSE 模式实现
├── sqlmap_mcp_stdio.py # 标准 I/O 模式实现
```

## 🤝 贡献指南  

我们欢迎社区贡献！如果您想改进此项目，请遵循以下步骤：  

1. **Fork 仓库**  
2. **创建功能分支**：`git checkout -b feature/new-feature`  
3. **提交代码**：`git commit -m "Add new feature"`  
4. **推送分支**：`git push origin feature/new-feature`  
5. **创建 Pull Request**  


## 📜 许可证  

本项目采用 [MIT 许可证](LICENSE)。    


## 📧 联系我们  

如有问题或建议，请在 GitHub 上提交 Issues 或联系项目维护者：  

- **邮箱**：2482552428@qq.com
- **GitHub**：https://github.com/ilikeoyt/sqlmap-mcp  


---

感谢使用 SQLMap MCP！我将持续改进这个工具，欢迎提出宝贵意见！