# AKA5G
5GAKA协议的python代码实现

Python 3.7.16



1. 启动前安装

   ```shell
   pip install cryptography
   ```

2. 启动

   先启动homeNetwork.py、servingNetwork.py，最后再启动subscriber.py

3. 重同步的模拟

   修改subscriber.py中的sqn_ue和homeNetwork.py中的sqn_hn，使sqn_ue>=sqn_hn

4. MAC错误的模拟

   将homeNetwork.py或subscriber.py中的`k = crypto.getKey()`改为`k = crypto.getKey(True)` （只需要修改一个）
