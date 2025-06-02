from typing import Any, Dict, Optional, List
import uuid
import asyncio
import subprocess
import os
import re
from enum import Enum
from mcp.server.fastmcp import FastMCP

# 初始化FastMCP服务器
mcp = FastMCP("sqlmap")

# 全局存储扫描任务
tasks: Dict[str, Dict[str, Any]] = {}
SQLMAP_PATH = "D:\\tools\\sqlmap\\sqlmap.py"  # 使用您指定的SQLMap路径


class ScanStatus(Enum):
    QUEUED = "queued"      # 已排队
    RUNNING = "running"    # 运行中
    COMPLETED = "completed"# 已完成
    FAILED = "failed"      # 已失败


async def run_sqlmap_scan(task_id: str, target_url: str, options: Dict[str, Any]) -> None:
    """异步执行sqlmap扫描并实时捕获输出"""
    try:
        # 确保任务存在
        if task_id not in tasks:
            return

        # 构建sqlmap命令
        cmd = [
            "python",
            SQLMAP_PATH,
            "-u", target_url,
            "--batch"  # 非交互模式
        ]

        # 添加额外选项
        if options:
            for key, value in options.items():
                if isinstance(value, bool) and value:
                    cmd.append(f"--{key}")
                elif isinstance(value, (int, float)):
                    cmd.append(f"--{key}={value}")
                elif isinstance(value, str):
                    cmd.append(f"--{key}={value}")

        # 更新任务状态
        tasks[task_id]["status"] = ScanStatus.RUNNING.value
        tasks[task_id]["command"] = " ".join(cmd)  # 保存命令用于调试
        tasks[task_id]["output"] = ""  # 初始化输出缓冲区
        tasks[task_id]["critical_lines"] = []  # 存储关键发现
        tasks[task_id]["vulnerabilities"] = []  # 存储结构化漏洞信息

        # 创建进程
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # 实时读取输出
        while True:
            # 逐行读取标准输出
            stdout_line = await process.stdout.readline()
            if stdout_line:
                line = stdout_line.decode('utf-8', errors='ignore').rstrip()
                tasks[task_id]["output"] += line + "\n"

                # 立即提取关键发现
                if "[CRITICAL]" in line:
                    tasks[task_id]["critical_lines"].append(line)

                # 实时提取漏洞信息
                if "is vulnerable" in line and "parameter" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        param = parts[1].strip("'")
                        vuln_type = " ".join(parts[3:])
                        tasks[task_id]["vulnerabilities"].append({
                            "parameter": param,
                            "type": vuln_type
                        })

            # 逐行读取错误输出
            stderr_line = await process.stderr.readline()
            if stderr_line:
                line = stderr_line.decode('utf-8', errors='ignore').rstrip()
                tasks[task_id]["output"] += "[ERROR] " + line + "\n"
                if "errors" not in tasks[task_id]:
                    tasks[task_id]["errors"] = []
                tasks[task_id]["errors"].append(line)
            # 检查进程是否已退出
            if process.stdout.at_eof() and process.stderr.at_eof():
                break

        # 等待进程完成
        return_code = await process.wait()

        # 更新任务状态
        if return_code == 0:
            tasks[task_id]["status"] = ScanStatus.COMPLETED.value
            # 解析最终结果
            parse_scan_results_from_output(task_id)
        else:
            tasks[task_id]["status"] = ScanStatus.FAILED.value

        # 保存最终信息
        tasks[task_id]["return_code"] = return_code
        tasks[task_id]["end_time"] = asyncio.get_event_loop().time()

    except Exception as e:
        if task_id in tasks:
            tasks[task_id].update({
                "status": ScanStatus.FAILED.value,
                "error": str(e),
                "end_time": asyncio.get_event_loop().time()
            })


def parse_scan_results_from_output(task_id: str) -> None:
    """改进的sqlmap输出解析器，处理各种格式"""
    try:
        if "output" not in tasks[task_id]:
            return

        output = tasks[task_id]["output"]
        results = []

        # 1. 使用更灵活的正则表达式提取注入点
        injection_points = re.findall(
            r"Parameter: (.+?) \(.+?\)\n((?:\s+Type: .+?\n\s+Title: .+?\n\s+Payload: .+?\n)+)",
            output,
            re.DOTALL
        )

        for param, vuln_block in injection_points:
            # 从块中提取每个漏洞
            vulns = re.findall(
                r"\s+Type: (.+?)\n\s+Title: (.+?)\n\s+Payload: (.+?)\n",
                vuln_block,
                re.DOTALL
            )
            for vuln in vulns:
                vuln_type, title, payload = vuln
                results.append({
                    "parameter": param,
                    "type": vuln_type.strip(),
                    "title": title.strip(),
                    "payload": payload.strip()
                })

        # 2. 处理新版本SQLMap的替代模式
        if not results:
            alt_points = re.findall(
                r"(\w+) parameter '(.+?)' (is vulnerable.+)",
                output
            )
            for method, param, details in alt_points:
                results.append({
                    "parameter": param,
                    "type": f"{method} - {details}"
                })

        # 3. 提取数据库信息
        db_info = re.search(
            r"back-end DBMS: (.+?)\n",
            output
        )
        if db_info:
            results.append({
                "type": "DBMS",
                "info": db_info.group(1).strip()
            })

        # 4. 添加关键行作为后备
        if "critical_lines" in tasks[task_id]:
            for line in tasks[task_id]["critical_lines"]:
                if "is vulnerable" in line:
                    results.append({
                        "type": "CRITICAL",
                        "info": line.replace("[CRITICAL] ", "")
                    })

        # 5. 添加实时检测到的漏洞
        if "vulnerabilities" in tasks[task_id]:
            for vuln in tasks[task_id]["vulnerabilities"]:
                # 避免重复
                if not any(r.get("parameter") == vuln["parameter"] for r in results):
                    results.append(vuln)

        if results:
            tasks[task_id]["results"] = results

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]["parse_error"] = str(e)


@mcp.tool()
async def start_scan(target_url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """启动一个新的SQLMap扫描任务

    Args:
        target_url: 要扫描的URL
        options: 额外的sqlmap选项 (例如 {"level": 3, "risk": 2})
    """
    task_id = str(uuid.uuid4())

    try:
        # 初始化任务
        tasks[task_id] = {
            "status": ScanStatus.QUEUED.value,
            "target_url": target_url,
            "options": options or {},
            "start_time": asyncio.get_event_loop().time(),
            "output": "",
            "results": None
        }

        # 在后台启动扫描
        asyncio.create_task(run_sqlmap_scan(task_id, target_url, options or {}))

        return {
            "task_id": task_id,
            "message": f"已开始扫描 {target_url}",
            "status_url": f"/scan/status/{task_id}"
        }

    except Exception as e:
        return {
            "task_id": task_id,
            "error": f"无法启动扫描: {str(e)}",
            "status": ScanStatus.FAILED.value
        }


@mcp.tool()
async def get_scan_status(task_id: str) -> Dict[str, Any]:
    """获取扫描任务的状态

    Args:
        task_id: 扫描任务的ID
    """
    if task_id not in tasks:
        return {"error": "无效的任务ID"}

    task = tasks[task_id]
    status = {
        "task_id": task_id,
        "status": task["status"],
        "target_url": task["target_url"],
    }

    # 添加时间信息
    current_time = asyncio.get_event_loop().time()
    if "start_time" in task:
        elapsed = current_time - task["start_time"]
        status["elapsed_time"] = f"{elapsed:.2f}s"

    # 添加结果或错误信息
    if "results" in task and task["results"]:
        status["results"] = task["results"]

    # 对于运行中的任务，显示部分输出
    if task["status"] == ScanStatus.RUNNING.value and "output" in task:
        # 显示最后20行输出
        lines = task["output"].splitlines()
        status["partial_output"] = "\n".join(lines[-20:])

    # 对于已完成的任务，显示摘要
    if task["status"] == ScanStatus.COMPLETED.value:
        if "output" in task:
            # 提取摘要信息
            summary = re.search(
                r"sqlmap identified the following injection point\(s\):(.+?)\n\n",
                task["output"],
                re.DOTALL
            )
            if summary:
                status["summary"] = summary.group(1).strip()
            else:
                status["summary"] = "未发现漏洞" if not task.get("results") else "发现漏洞"

    # 对于失败的任务，显示错误详情
    if task["status"] == ScanStatus.FAILED.value:
        if "error" in task:
            status["error"] = task["error"]
        elif "errors" in task and task["errors"]:
            status["error"] = task["errors"][-1]  # 显示最后一个错误
        elif "output" in task:
            # 尝试在输出中查找错误
            error_match = re.search(r"\[ERROR\] (.+)", task["output"])
            if error_match:
                status["error"] = error_match.group(1)

    # 添加调试信息
    if "command" in task:
        status["command"] = task["command"]

    return status


@mcp.tool()
async def list_scans(include_completed: bool = True) -> Dict[str, Any]:
    """列出所有扫描任务

    Args:
        include_completed: 是否包含已完成的任务
    """
    active_tasks = []
    completed_tasks = []

    for task_id, task in tasks.items():
        task_info = {
            "task_id": task_id,
            "status": task["status"],
            "target_url": task["target_url"],
            "start_time": task.get("start_time", 0)
        }

        if task["status"] in [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]:
            active_tasks.append(task_info)
        elif include_completed and task["status"] in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value]:
            task_info["end_time"] = task.get("end_time", 0)
            completed_tasks.append(task_info)

    return {
        "active_tasks": active_tasks,
        "completed_tasks": completed_tasks
    }


if __name__ == "__main__":
    # 初始化并运行服务器
    mcp.run(transport='stdio')