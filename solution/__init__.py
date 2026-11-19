"""离线应用执行控制服务（Application Execution Control, offline）。

仅使用 Python 3.12 标准库，模拟企业安全代理在启动软件前向本地白名单
服务申请准入的全过程。服务只把判定结果写入合成启动清单，从不运行被
申请的程序。
"""

__version__ = "1.0.0"
