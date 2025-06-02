import asyncio
import subprocess
import re
from mcp.server.fastmcp import FastMCP
import logging

# 初始化 FastMCP 服务器
mcp = FastMCP("sqlmap")


# 定义结果解析器类
class SQLMapResultParser:
    @staticmethod
    def parse(output: str) -> dict:
        """解析SQLMap输出并提取结构化信息"""
        result = {
            "vulnerabilities": [],
            "database_info": {},
            "injection_points": [],
            "payloads": {}
        }

        # 提取漏洞类型
        vuln_patterns = {
            "布尔型盲注": r"Boolean-based blind SQL injection detected",
            "基于错误的注入": r"Error-based SQLi detected",
            "时间型盲注": r"Time-based blind SQL injection detected",
            "UNION查询注入": r"UNION query\.+?: SQL injection"
        }

        for vuln_type, pattern in vuln_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                result["vulnerabilities"].append(vuln_type)

        # 提取数据库信息
        db_type_match = re.search(r"back-end DBMS: (.+)", output)
        if db_type_match:
            result["database_info"]["type"] = db_type_match.group(1).strip()

        tech_match = re.search(r"web application technology: (.+)", output)
        if tech_match:
            result["database_info"]["technology"] = tech_match.group(1).strip()

        # 提取注入点参数
        param_match = re.search(r"Parameter: (\w+) \[", output)
        if param_match:
            result["injection_points"].append({
                "type": "GET",
                "parameter": param_match.group(1)
            })

        # 提取示例载荷
        payload_patterns = {
            "布尔型盲注": r"Boolean-based blind SQL injection payload: (.*)",
            "基于错误注入": r"Error-based payload: (.*)",
            "时间型盲注": r"Time-based payload: (.*)",
            "UNION注入": r"UNION query payload: (.*)"
        }

        for payload_type, pattern in payload_patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                result["payloads"][payload_type] = match.group(1).strip()

        return result

    @staticmethod
    def format_to_markdown(result: dict) -> str:
        """将解析结果格式化为Markdown文本"""
        md = "# SQL注入检测报告\n\n"

        # 添加漏洞信息
        if result["vulnerabilities"]:
            md += "## 检测到的漏洞类型\n"
            for vuln in result["vulnerabilities"]:
                md += f"- {vuln}\n"
            md += "\n"
        else:
            md += "## 检测结果\n未发现SQL注入漏洞\n\n"
            return md

        # 添加数据库信息
        if result["database_info"]:
            md += "## 数据库信息\n"
            for key, value in result["database_info"].items():
                md += f"- **{key.capitalize()}**: {value}\n"
            md += "\n"

        # 添加注入点信息
        if result["injection_points"]:
            md += "## 注入点参数\n"
            for point in result["injection_points"]:
                md += f"- **{point['type']}参数**: {point['parameter']}\n"
            md += "\n"

        # 添加示例载荷
        if result["payloads"]:
            md += "## 示例攻击载荷\n"
            for payload_type, payload in result["payloads"].items():
                md += f"- **{payload_type}**: {payload}\n"
            md += "\n"

        # 添加修复建议
        md += "## 安全建议\n"
        md += "1. 立即修复此漏洞，可以通过参数化查询或使用预处理语句来防止SQL注入攻击\n"
        md += "2. 对用户输入进行严格的验证和过滤\n"
        md += "3. 限制数据库用户权限，降低攻击影响\n"

        return md


async def run_sqlmap(url: str, sqlmap_args: list[str]) -> str:
    """异步执行 SQLMap 并返回字符串结果"""
    try:
        print(f"[DEBUG] 开始执行 SQLMap: {url}")
        process = await asyncio.create_subprocess_exec(
            "python",
            "D:\\tools\\sqlmap\\sqlmap.py",
            "-u", url,
            *sqlmap_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            text=False  # 必须为 False，手动处理编码
        )

        # 使用 asyncio.wait_for 设置超时
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=7200  # 2小时超时
        )

        # 手动解码输出
        stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ""
        stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ""

        if process.returncode == 0:
            print(f"[DEBUG] SQLMap 执行成功 (返回码: {process.returncode})")
            return stdout_str if stdout_str else stderr_str
        else:
            print(f"[DEBUG] SQLMap 执行失败 (返回码: {process.returncode})")
            return f"SQLMap 执行失败 (返回码: {process.returncode})\n{stderr_str}"

    except asyncio.TimeoutError:
        print("[DEBUG] SQLMap 执行超时")
        return "SQLMap 执行超时 (7200秒)"

    except Exception as e:
        print(f"[DEBUG] 执行 SQLMap 时发生异常: {str(e)}")
        return f"执行异常: {str(e)}"


@mcp.tool()
async def sqlmap_scan(url: str, sqlmap_args: list[str] = []) -> str:
    """使用 SQLMap 对目标 URL 进行 SQL 注入扫描"""
    # 添加 --batch 参数确保非交互式执行
    full_args = ["--batch"] + sqlmap_args

    # 执行 SQLMap 并获取结果
    output = await run_sqlmap(url, full_args)

    # 解析结果并格式化
    if "开始检测" in output or "检测到" in output:
        parser = SQLMapResultParser()
        parsed_result = parser.parse(output)
        formatted_output = parser.format_to_markdown(parsed_result)
        return formatted_output
    else:
        # 如果无法解析结果，返回原始输出
        return output if isinstance(output, str) else str(output)


if __name__ == "__main__":
    # 使用正确的异步运行方式
    try:
        print("[INFO] 启动 SQLMap MCP 服务器...")
        mcp.run()
    except KeyboardInterrupt:
        print("[INFO] 服务器已停止")