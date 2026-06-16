import requests
# 导入 urllib3 用来消除安全警告（可选，能让控制台输出更干净）
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. 核心修改：改走 https 协议，目标依然是本地 127.0.0.1
TARGET_URL = "https://127.0.0.1/"

# 2. 核心修改：定义固定的头部，伪装 Host 域名，让 Nginx 能够成功匹配 server_name
DEFAULT_HEADERS = {
    "Host": "www.ctalk.me"
}

# 测试用例定义
test_cases = [
    # ---- 恶意攻击测试 (预期全部被拦截：403) ----
    ("SQL 注入漏洞", "ARGS", {"id": "' or 1=1--"}, True),
    ("XSS 跨站脚本", "ARGS", {"text": "<img src=x onerror=alert(1)>"}, True),
    ("路径穿越漏洞", "ARGS", {"path": "../../../../etc/passwd"}, True),
    ("远程命令执行", "ARGS", {"exec": "; rm -rf / ;"}, True),
    ("恶意扫描器User-Agent", "HEADERS", {"User-Agent": "Nikto/2.1.6"}, True),
    ("Struts2 漏洞特征", "HEADERS", {"Content-Type": "%{(#factory=@org.apache.struts2.json.JSONUtil@class).net}"}, True),
    
    # ---- 正常业务测试 (预期全部放行：不能是 403) ----
    ("正常首页访问", "ARGS", {}, False),
    ("正常聊天消息", "ARGS", {"message": "Hello, how are you? I will send you a file tomorrow."}, False),
    ("正常用户名密码", "ARGS", {"username": "admin_test", "password": "SecurePassword123!"}, False),
]

def run_tests():
    print("=" * 60)
    print("                ModSecurity CRS WAF 自动化测试                ")
    print("=" * 60)
    
    passed_count = 0
    
    for name, t_type, payload, expect_block in test_cases:
        try:
            # 3. 核心修改：合并 Host 头部，同时增加 verify=False 绕过证书域名检测
            if t_type == "ARGS":
                response = requests.get(TARGET_URL, params=payload, headers=DEFAULT_HEADERS, timeout=5, verify=False)
            elif t_type == "HEADERS":
                # 如果用例本身要测试特定的 Header（如 User-Agent），就把默认的 Host 融进去
                merged_headers = {**DEFAULT_HEADERS, **payload}
                response = requests.get(TARGET_URL, headers=merged_headers, timeout=5, verify=False)
            
            status_code = response.status_code
            is_blocked = (status_code == 403)
            
            # 判断测试是否符合预期
            if is_blocked == expect_block:
                result_str = "【 ✅ 通过 】"
                passed_count += 1
            else:
                result_str = "【 ❌ 失败 】"
                
            print(f"{result_str} 测试项: {name:<20} | 响应状态码: {status_code:<3} | 预期拦截: {str(expect_block):<5}")
            
        except Exception as e:
            print(f"【 ❌ 错误 】 测试项: {name:<20} | 无法连接到服务器: {e}")
            
    print("=" * 60)
    print(f"测试完成: 成功 {passed_count}/{len(test_cases)} 个用例。")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
