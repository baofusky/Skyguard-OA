import streamlit as st
from datetime import datetime
import requests
import time
import hmac
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import uuid
import json
import io
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
import base64

# 初始化会话状态
if 'file_content_public' not in st.session_state:
    st.session_state['file_content_public'] = {"content": "", "filename": "", "uploaded_at": ""}

if 'token_info' not in st.session_state:
    st.session_state['token_info'] = {"client-id": "", "access-token": ""}

if 'ucwi_credentials' not in st.session_state:
    st.session_state['ucwi_credentials'] = {
        "ip_address": "",
        "port": "",
        "app_id": "",
        "access_key": "",
        "secret_key": ""
    }

if 'ucss_credentials' not in st.session_state:
    st.session_state['ucss_credentials'] = {
        "ip_address": "",
        "port": "",
        "microservice_key": "",
        "account": "",
        "password": ""
    }

if 'http_response' not in st.session_state:
    st.session_state['http_response'] = ""

if 'incident_info' not in st.session_state:
    st.session_state['incident_info'] = ""

if 'action_code' not in st.session_state:
    st.session_state['action_code'] = ""


def checkin():
    key = st.session_state['ucss_credentials']['microservice_key'].encode('utf-8')
    plaintext =st.session_state['ucss_credentials']['password'].encode('utf-8')
    padded_plaintext = pad(plaintext, DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plaintext)
    base64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    url = f"https://{st.session_state['ucss_credentials']['ip_address']}:{st.session_state['ucss_credentials']['port']}/qkact/v1/checkin"
    username = st.session_state['ucss_credentials']['account']
    auth_base64 = base64.b64encode("{}:{}".format(username, base64_ciphertext).encode("utf-8")).decode("utf-8")
    auth = "Basic {}".format(auth_base64)
    headers = {
        "Authorization": auth,
        "User-Agent": "QKAct-External-Client",
        "Content-Type": "application/json",
    }
    body = {
        "client-id": "5817AFB7-A263-43CA-BD2A-39C93E36210C"
    }
    try:
        response = requests.post(url, headers=headers, json=body, verify=False)
        response.raise_for_status()
        response_json = response.json()
        st.write(response_json)
        st.write(username)
        st.write(base64_ciphertext)
        token = response.json()["access-token"]
        id = response.json()["client-id"]
        st.session_state['token_info'] ={
            "client-id":id,
            "access-token":token,
        }
        newtoken = st.session_state['token_info']['access-token']
        st.write(f'-token是{newtoken}')
        newclinentid=st.session_state['token_info']['client-id']
        st.write(f'-客户端id是{newclinentid}')

    except requests.RequestException as e:
        st.error(f"checkin的时候发生错误: {e}")
        st.write(username)
        st.write(base64_ciphertext)
        return ""




def ucss_credentials_form():
    st.header("请提供UCSS的IP地址和账号和密码")

    ip_address = st.text_input("IP地址", value=st.session_state['ucss_credentials']['ip_address'])
    port = st.number_input("端口", value=int(st.session_state['ucss_credentials']['port']) if
    st.session_state['ucss_credentials']['port'] else 8443)
    account = st.text_input("ucss管理员账号", value=st.session_state['ucss_credentials']['account'])
    password = st.text_input("UCSS管理员密码", type="password")
    microservice_key = st.text_input("管理员微服账号", value=st.session_state['ucss_credentials']['microservice_key'])

    if st.button("保存UCSS信息"):
        st.session_state['ucss_credentials'] = {
            "ip_address": ip_address,
            "port": str(port),
            "account": account,
            "password": password,
            "microservice_key": microservice_key
        }
        st.success("UCSS信息已保存")

    if st.button("Checkin"):
        checkin()


def file_info_form():
    st.header("请提供文件审批用的详细信息")
    options = ["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30"]
    approver = st.text_input("审批人(必写)", value="admin")
    submitter_name = st.text_input("提交人")
    submitter_ip = st.text_input("提交人IP", value="192.168.0.2")
    submitter_email = st.text_input("提交人邮箱", value="user1@test.com")
    file_size = st.text_input("文件大小-单位B,不能为空")
    file_md5 = st.text_input("文件md5(必写)")
    file_name = st.text_input("文件名")
    approved_time = st.text_input("审批时间", value="2024-07-25 13:00:00")
    expired_time = st.text_input("审批过期时间", value="2024-07-25 13:00:00")
    max_num = st.number_input("最大通过次数",value=3)
    submitter_fqdn = st.text_input("机器的FQDN")
    channel = st.multiselect("请选择通道",options,default=["1","2","3","4","5","6"])
    forensic = st.number_input("是否记录证据", value=1)

    if st.button("查看通道列表"):
        st.write("""     
    1	网络HTTP
    2	网络HTTPS
    3	网络FTP
    4	IM
    5	邮件SMTP
    6	自定义协议
    7	数据发现
    8	网络打印
    9	IMAP（终端）
    10	POP3（终端）
    11	HTTP（终端）
    12	HTTPS（终端）
    13	FTP（终端）
    14	IM（终端）
    15  SMTP（终端）
    16	自定义协议（终端）
    17	数据发现
    18	终端打印
    19	移动存储
    20	网络共享
    21	刻录
    22	应用程序
    23	蓝牙
    24	红外
    25	WebService应用
    26	文件共享
    27	ActiveSync
    28	本地存储
    29	HTTP（移动）
    30	HTTPS（移动）
    """)
    if st.button("保存信息"):
        pass

    if st.button("提交审批"):
        pass

def get_auth(access_key, secret_key, timestamp):
    token_source = secret_key + timestamp
    token = hmac.new(
        secret_key.encode('utf-8'),
        token_source.encode('utf-8'),
        hashlib.sha256).hexdigest()
    return "SKG {0}:{1}".format(access_key, token)


def get_headers():
    timestamp = "{0:.0f}".format(time.time())
    auth = get_auth(
        st.session_state['ucwi_credentials']['access_key'],
        st.session_state['ucwi_credentials']['secret_key'],
        timestamp)

    headers = {
        "X-Skg-Timestamp": timestamp,
        "authorization": auth,
    }
    return headers


def send_to_ucwi(file_content, filename):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    url = f"https://{st.session_state['ucwi_credentials']['ip_address']}:{st.session_state['ucwi_credentials']['port']}/skg/v1/dlp/channel/cloudapp/{st.session_state['ucwi_credentials']['app_id']}/sync"
    # print(url)
    headers = get_headers()
    metadata = {
        "user": "cnsec_jizhiming",
        # "filename": "mimi.txt",
        "queryID": str(uuid.uuid4()),
        # "md5": "e569660a0bc41a34d7d7aa12cb29feac",
        "operation": 1,
        # "antivirus": True,
        # "encoding": "UTF-8",
    }
    data = {"metadata": json.dumps(metadata)}

    # 将文件内容转换为BytesIO对象，模拟文件上传
    # file_like_object = io.BytesIO(file_content.encode('utf-8'))
    files = {'request': (filename, file_content, 'text/plain')}  # 文件名，文件内容，MIME类型

    try:
        response = requests.post(url, data=data, headers=headers, files=files, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        st.error(f"请求UCWI时发生错误,未正常响应: {e}")
        return ""


def process_http_response(response_text):
    try:
        response_json = json.loads(response_text)
        incident_info = response_json.get("incident_info")
        st.session_state['incident_info'] = incident_info
        # print(incident_info)

        # if incident_info is None:
        if len(incident_info) == 0:
            st.success("UCWI：外发文件无敏感内容")
            # 直接COPY文件到公开区域的逻辑应在此处实现，但基于现有代码结构，该部分逻辑已在update_public_content中处理。

        else:
            # 增加风险分析展示区域
            st.warning("UCWI：外发文件存在敏感内容，触发策略")

            action_code = response_json.get("actionCode")
            st.session_state['action_code'] = action_code
            policy_name = incident_info.get("matchedPolicies")[0]["name"]
            severity = incident_info.get("matchedPolicies")[0]["severity"]
            if severity == 1:
                severity = "高"
            elif severity == 2:
                severity = "中"
            elif severity == 3:
                severity = "低"
            elif severity == 4:
                severity = "信息"

            actionSettingName = incident_info.get("matchedPolicies")[0]["actionSettingName"]
            numberOfMatches = incident_info.get("matchedPolicies")[0]["numberOfMatches"]
            st.write(f"- 策略名称: {policy_name}")
            st.write(f"- 策略安全等级: {severity}")
            st.write(f"- 策略动作: {actionSettingName}")
            st.write(f"- 命中规则数: {numberOfMatches}")

            # if strategy_name:
            # st.write(f"- 策略名称: {strategy_name}")
            # st.write(f"- 策略危险等级: {severity}")

            if action_code == 2:
                st.error("文件中转系统：外发文件存在敏感内容，禁止发送")
            elif action_code == 1:
                st.warning("文件中转系统：外发文件可能存在风险，外发动作已被平台审计")

            # 实现存储策略到下拉框的逻辑需要前端界面的调整，此处简化处理仅展示信息。

    except json.JSONDecodeError:
        st.error("无法解析UCWI的响应为JSON格式")


def update_public_content(file_content, filename):
    """更新公开区域的文件内容，如果UCWI认证信息完整则同时发送到UCWI"""
    # 更新公开区域的文件内容
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['file_content_public'] = {
        "content": file_content,
        "filename": filename,
        "uploaded_at": now
    }

    # 检查ucwi_credentials是否全部填写
    if all(st.session_state['ucwi_credentials'].values()):
        response_text = send_to_ucwi(file_content, filename)
        st.session_state['http_response'] = response_text

        process_http_response(response_text)

        if not st.session_state['incident_info'] or st.session_state['action_code'] == 1:
            # st.success("内容已上传到公开区域并发送至UCWI:外发文件无敏感内容")
            st.success("文件流转系统：内容已上传到公开区域")
        else:
            st.session_state['file_content_public'] = {
                "content": '',
                "filename": '',
                "uploaded_at": ''
            }

    else:
        st.success("内容已上传到公开区域")


def private_area():
    st.header("内部区域")

    uploaded_file = st.file_uploader("上传TXT文件", type=['txt'])

    if uploaded_file is not None:
        file_content = uploaded_file.read().decode('utf-8')
        st.text_area("文件预览", value=file_content, height=300)
        filename = uploaded_file.name

        if st.button("上传到公开区域"):
            update_public_content(file_content, filename)

            # 如果UCWI认证信息未填写完整，这部分不进行显示
            if all(st.session_state['ucwi_credentials'].values()):
                # 构造HTTP请求的展示文本
                request_details = (
                    f"URL: https://{st.session_state['ucwi_credentials']['ip_address']}:{st.session_state['ucwi_credentials']['port']}\n"
                    f"Method: POST\n"
                    f"Headers:\n"
                    f"  - access_key: {st.session_state['ucwi_credentials']['access_key']}\n"
                    f"  - secret_key: {st.session_state['ucwi_credentials']['secret_key']}\n"
                    f"Payload:\n"
                    f"  - filename: {filename}\n"
                    f"  - content: {file_content[:50]}... (truncated for preview)"
                )

                # 使用expander组件创建一个可折叠的HTTP请求展示区域
                with st.expander("HTTP Requests", expanded=False):
                    st.code(request_details, language='plaintext')

                with st.expander("HTTP Response", expanded=False):
                    st.code(st.session_state['http_response'], language='plaintext')


def public_area():
    st.header("公开区域")

    content_info = st.session_state['file_content_public']

    if content_info["content"]:
        st.write(f"**文件名:** {content_info['filename']}")
        st.write(f"**上传时间:** {content_info['uploaded_at']}")
        st.text_area("文件内容预览", value=content_info["content"], height=300)


def login():
    """用户认证函数"""
    st.title("Skyguard终端文件审批测试平台")

    # 写死的用户名和密码
    correct_username = "admin"
    correct_password = "Firewall1!"

    username = st.text_input("用户名")
    password = st.text_input("密码", type="password")

    if st.button("登录"):
        if username == correct_username and password == correct_password:
            st.success("登录成功!")
            # 设置一个会话状态表示已登录，这样就可以控制页面访问权限了
            st.session_state['logged_in'] = True
            # 登录成功后，可以重定向到内部区域，这里使用 Streamlit 的 experimental_rerun 函数
            # import streamlit as st
            st.experimental_rerun()
        else:
            st.error("用户名或密码错误，请重试。")


# 修改main函数以包含登录逻辑
def main():
    # 初始化会话状态，添加登录状态
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    # 如果用户未登录，则显示登录表单
    if not st.session_state['logged_in']:
        login()
    else:
        # st.set_page_config(layout="wide")

        tabs = ["UCSS信息", "文件审批信息"]
        choice = st.sidebar.radio("菜单", tabs)

        if choice == "UCSS信息":
            ucss_credentials_form()
        elif choice == "文件审批信息":
            file_info_form()


if __name__ == "__main__":
    main()