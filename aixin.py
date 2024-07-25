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

if 'token_info' not in st.session_state:
    st.session_state['token_info'] = {"client-id": "", "access-token": ""}

if 'ucss_credentials' not in st.session_state:
    st.session_state['ucss_credentials'] = {
        "ip_address": "",
        "port": "",
        "microservice_key": "",
        "account": "",
        "password": ""
    }

if 'file_info' not in st.session_state:
    st.session_state['file_info'] = {
        "approver": "",
        "submitter_ip":"",
        "submitter_name": "",
        "submitter_email": "",
        "submitter_fqdn": "",
        "file_size": "",
        "file_md5": "",
        "file_name": "",
        "approved_time": "",
        "expired_time": "",
        "max_num": "",
        "forensic": "",
        "channel":""
    }

def translatetout(normaltime):
    timeArray = time.strptime(normaltime,"%Y-%m-%d %H:%M:%S")
    timeStamp = int(time.mktime(timeArray))

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
    st.write("请先在[UCSS信息]界面填写UCSS信息，并保存UCSS信息后，再checkin,正常checkin之后再切到[文件审批信息]界面填写文件审批信息，之后保存后再提交审批")
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
        if st.session_state['ucss_credentials']['ip_address'] == "" or st.session_state['ucss_credentials']['port'] == "" or st.session_state['ucss_credentials']['password']== "" or st.session_state['ucss_credentials']['microservice_key']== "":
            st.write("信息填写不全，请重新检查，填写完整信息后,点[保存UCSS信息后]再chec-kin")
        else:
            checkin()


def file_info_form():
    st.write("请先填写文件审批需要的信息，然后点保存之后再提交审批，审批成功之后，请到UCSS--监控--DLP监控--审批记录，查询审批记录")
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
    d1='{}'.format(approved_time)
    d11=translatetout(d1)
    d2='{}'.format(expired_time)
    d22=translatetout(d2)


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
        st.session_state['file_info'] = {
            "approver": approver,
            "submitter_name": submitter_name,
            "submitter_ip":submitter_ip,
            "submitter_email": submitter_email,
            "submitter_fqdn": submitter_fqdn,
            "file_size": file_size,
            "file_md5":file_md5,
            "file_name": file_name,
            "approved_time": d11,
            "expired_time": d22,
            "max_num": max_num,
            "forensic":forensic,
            "channel":channel
        }
        st.success("文件信息已保存")
    if st.button("提交审批"):

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        url = f"https://{st.session_state['ucss_credentials']['ip_address']}:{st.session_state['ucss_credentials']['port']}/qkact/v1/dlp/incident/approval"
        clientId = st.session_state['token_info']['client-id']
        accessToken = st.session_state['token_info']['access-token']
        auth_base64 = base64.b64encode("{}:{}".format(clientId, accessToken).encode("utf-8")).decode("utf-8")
        auth = "Basic {}".format(auth_base64)
        headers = {
            "Authorization": auth,
            "User-Agent": "QKAct-External-Client",
            "Content-Type": "application/json",
        }
        body = {
            "data": [{
                "approver": approver,
                "submitter_name": submitter_name,
                "submitter_ip": submitter_ip,
                "submitter_email": submitter_email,
                "submitter_fqdn": submitter_fqdn,
                "file_size": file_size,
                "file_md5": file_md5,
                "file_name": file_name,
                "approved_time": d11,
                "expired_time": d22,
                "max_num": max_num,
                "forensic": forensic,
                "channel": channel
            }]
        }
        try:
            response = requests.post(url, headers=headers, json=body, verify=False)
            response.raise_for_status()
            response_json = response.json()
            st.write(response_json)
            if response_json['reason'] == "Success":
                st.write(f"已经正常提交审批，请去{st.session_state['ucss_credentials']['ip_address']}查看审批记录")

        except requests.RequestException as e:
            st.error(f"checkin的时候发生错误: {e}")
            st.write(username)
            st.write(base64_ciphertext)
            return ""

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