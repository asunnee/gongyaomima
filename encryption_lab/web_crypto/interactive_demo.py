# interactive_demo.py
from encryption_platform import EncryptionPlatform

def main():
    print("===== 公钥加密算法实验平台 =====")
    print("可选算法：\n1. RSA\n2. ElGamal\n3. ECC")
    algo_map = {"1": "RSA", "2": "ElGamal", "3": "ECC"}

    choice = input("请选择算法 (输入 1/2/3)：").strip()
    if choice not in algo_map:
        print("无效的选择！程序退出。")
        return

    algo_name = algo_map[choice]
    print(f"\n[√] 你选择的算法是：{algo_name}")

    # 生成密钥
    platform = EncryptionPlatform()
    pub_key, priv_key = platform.generate_keys(algo_name)
    print("\n[√] 密钥生成成功！")
    print(f"公钥：{pub_key}")
    print(f"私钥：{priv_key}")

    last_ciphertext = None

    # 进入加密/解密/退出 循环
    while True:
        print("\n请选择操作：")
        print("1. 加密")
        print("2. 解密（直接回车使用上次加密结果）")
        print("3. 退出")
        op = input("输入选项 (1/2/3)：").strip()

        if op == "1":  # 加密
            plaintext = input("请输入要加密的明文：").strip()

            # 数字算法需要整数
            if algo_name in ["RSA", "ElGamal"]:
                try:
                    plaintext = int(plaintext)
                except ValueError:
                    print("错误：该算法只支持加密整数，请重新输入。")
                    continue

            last_ciphertext = platform.encrypt(algo_name, plaintext, pub_key)
            # 一次性完整输出，不要自动换行
            print(f"[√] 加密成功！\n密文：{last_ciphertext}")

        elif op == "2":  # 解密
            if last_ciphertext is None:
                ciphertext_input = input("请输入要解密的密文：").strip()
            else:
                inp = input("请输入要解密的密文（回车则使用上次结果）: ").strip()
                ciphertext_input = inp if inp else str(last_ciphertext)

            try:
                if algo_name == "RSA":
                    c = int(ciphertext_input)
                    plaintext = platform.decrypt(algo_name, c, priv_key)
                elif algo_name == "ElGamal":
                    if ciphertext_input.startswith("("):
                        c = eval(ciphertext_input, {}, {})
                    else:
                        a_str, b_str = ciphertext_input.split(",", 1)
                        c = (int(a_str), int(b_str))
                    plaintext = platform.decrypt(algo_name, c, priv_key, pub_key)
                else:  # ECC
                    plaintext = platform.decrypt(algo_name, ciphertext_input, priv_key)

                print(f"[√] 解密成功！\n明文：{plaintext}")
            except Exception as e:
                print(f"解密失败：{e}，请检查密文格式后重试。")

        elif op == "3":  # 退出
            print("退出程序，拜拜！")
            break

        else:
            print("无效的选项，请输入 1、2 或 3。")

if __name__ == "__main__":
    main()
