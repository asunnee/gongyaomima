import time
import random
import string
import math
from collections import Counter
import matplotlib.pyplot as plt
from encryption_platform import EncryptionPlatform
import numpy as np
import json  # 新增

plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

def measure_time(func, *args, repeat=3):
    total = 0
    for _ in range(repeat):
        start = time.perf_counter()
        func(*args)
        total += time.perf_counter() - start
    return total / repeat

def generate_random_plaintext(algo):
    length = random.choice([10, 50, 100])
    if algo in ["RSA", "ElGamal"]:
        return int(''.join(random.choices(string.digits, k=length)))
    elif algo == "ECC":
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    else:
        raise ValueError("不支持的算法类型")

def calculate_entropy(data):
    if not data:
        return 0.0
    counter = Counter(str(data))
    length = len(data)
    entropy = -sum((freq / length) * math.log2(freq / length) for freq in counter.values())
    return entropy

def serialize_cipher(cipher):
    """
    统一序列化密文，避免碰撞统计误差。
    - 如果是元组或列表，转成JSON字符串。
    - 否则直接转字符串。
    """
    if isinstance(cipher, (tuple, list, dict)):
        return json.dumps(cipher, sort_keys=True)
    else:
        return str(cipher)

def fixed_plaintext_collision_test(algo, plain, rounds=20):
    """
    固定明文碰撞测试：
    用相同明文，遍历多轮各自生成的公钥，分别加密，统计密文碰撞数。
    """
    platform = EncryptionPlatform()
    ciphertexts = []
    entropy_list = []

    for _ in range(rounds):
        public_key, private_key = platform.generate_keys(algo)
        cipher = platform.encrypt(algo, plain, public_key)
        serialized_cipher = serialize_cipher(cipher)
        ciphertexts.append(serialized_cipher)
        entropy_list.append(calculate_entropy(serialized_cipher))

    unique_ciphertexts = len(set(ciphertexts))
    collision_count = rounds - unique_ciphertexts
    avg_entropy = np.mean(entropy_list)
    std_entropy = np.std(entropy_list)

    print(f"\n  固定明文碰撞测试")
    print(f"  固定明文: {plain}")
    print(f"  轮数: {rounds}")
    print(f"  不同密文数量: {unique_ciphertexts}")
    print(f"  碰撞次数: {collision_count}")
    print(f"  平均信息熵: {avg_entropy} bits/char")
    print(f"  熵标准差: {std_entropy} bits/char")

    return collision_count, avg_entropy, std_entropy

def evaluate_algorithm(algo, rounds=10, fixed_plaintext_repeat=20):
    platform = EncryptionPlatform()
    print(f"\n[{algo}] 性能与安全性测试开始...")

    keygen_times, enc_times, dec_times, cipher_lengths = [], [], [], []
    entropies = []

    fixed_plain = generate_random_plaintext(algo)

    for i in range(rounds):
        print(f"  - 第 {i + 1} 轮测试...")

        start = time.perf_counter()
        public_key, private_key = platform.generate_keys(algo)
        keygen_time = time.perf_counter() - start
        keygen_times.append(keygen_time)

        print(f"    公钥: {public_key}")
        print(f"    私钥: {private_key}")

        plain = generate_random_plaintext(algo)

        t_enc = measure_time(platform.encrypt, algo, plain, public_key)
        cipher = platform.encrypt(algo, plain, public_key)
        enc_times.append(t_enc)

        cipher_str = serialize_cipher(cipher)
        cipher_lengths.append(len(cipher_str))
        entropy = calculate_entropy(cipher_str)
        entropies.append(entropy)

        if algo == "ElGamal":
            args = (algo, cipher, private_key, public_key)
        else:
            args = (algo, cipher, private_key)
        t_dec = measure_time(platform.decrypt, *args)
        dec_times.append(t_dec)

        decrypted = platform.decrypt(*args)

        print(f"    明文：{plain}")
        print(f"    密文：{cipher}")
        print(f"    解密后明文：{decrypted}")
        print(f"    熵值：{entropy}\n")

    fpc, fpe, fpe_std = fixed_plaintext_collision_test(algo, fixed_plain, rounds=fixed_plaintext_repeat)

    avg_keygen = sum(keygen_times) / rounds
    avg_enc = sum(enc_times) / rounds
    avg_dec = sum(dec_times) / rounds
    avg_cipher_len = sum(cipher_lengths) / rounds
    avg_entropy = sum(entropies) / rounds
    entropy_std = np.std(entropies)

    print(f"\n平均密钥生成时间: {avg_keygen} 秒")
    print(f"平均加密时间: {avg_enc} 秒")
    print(f"平均解密时间: {avg_dec} 秒")
    print(f"平均密文长度: {avg_cipher_len} 字符")
    print(f"平均信息熵: {avg_entropy} ± {entropy_std} bits/char")
    print(f"固定明文碰撞次数: {fpc}\n")

    return {
        "keygen": avg_keygen,
        "enc": avg_enc,
        "dec": avg_dec,
        "cipher_len": avg_cipher_len,
        "entropy": avg_entropy,
        "entropy_std": entropy_std,
        "fixed_plaintext_collision": fpc,
        "fixed_entropy": fpe,
        "fixed_entropy_std": fpe_std
    }

def add_labels(ax, rects, values=None):
    for i, rect in enumerate(rects):
        height = rect.get_height()
        if values:
            # values[i] 是元组：(mean, std)，格式化为 4位小数 ± 4位小数 bits/char
            text = f"{values[i][0]:.4f} ± {values[i][1]:.4f} bits/char"
        else:
            text = f'{height:.6f}'
        ax.annotate(text,
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9)

def plot_results(results):
    algos = list(results.keys())
    keygen = [results[a]["keygen"] for a in algos]
    enc = [results[a]["enc"] for a in algos]
    dec = [results[a]["dec"] for a in algos]
    clen = [results[a]["cipher_len"] for a in algos]
    entropy = [results[a]["entropy"] for a in algos]
    entropy_std = [results[a]["entropy_std"] for a in algos]
    fixed_collisions = [results[a]["fixed_plaintext_collision"] for a in algos]
    fixed_entropy = [results[a]["fixed_entropy"] for a in algos]
    fixed_entropy_std = [results[a]["fixed_entropy_std"] for a in algos]

    x = range(len(algos))
    bar_width = 0.2

    plt.figure(figsize=(12, 6))
    ax = plt.gca()
    r1 = ax.bar([i - bar_width for i in x], keygen, width=bar_width, label="密钥生成时间")
    r2 = ax.bar(x, enc, width=bar_width, label="加密时间")
    r3 = ax.bar([i + bar_width for i in x], dec, width=bar_width, label="解密时间")
    add_labels(ax, r1)
    add_labels(ax, r2)
    add_labels(ax, r3)
    plt.xlabel("加密算法")
    plt.ylabel("平均耗时（秒）")
    plt.title("加密算法时间性能对比图")
    plt.xticks(x, algos)
    plt.legend()
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    ax = plt.gca()
    bars = ax.bar(algos, clen, color="orange")
    add_labels(ax, bars)
    plt.xlabel("加密算法")
    plt.ylabel("平均密文长度（字符）")
    plt.title("加密算法扩展性对比")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    ax = plt.gca()
    bars = ax.bar(algos, entropy, yerr=entropy_std, color="green", capsize=5)
    # 传入格式化数值元组 [(mean, std), ...]
    values = list(zip(entropy, entropy_std))
    add_labels(ax, bars, values)
    plt.xlabel("加密算法")
    plt.ylabel("平均信息熵（bits/char）")
    plt.title("密文信息熵强度比较")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    ax = plt.gca()
    bars = ax.bar(algos, fixed_collisions, color="purple")
    add_labels(ax, bars)
    plt.xlabel("加密算法")
    plt.ylabel("固定明文碰撞次数")
    plt.title("固定明文多次加密碰撞测试")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    ax = plt.gca()
    bars = ax.bar(algos, fixed_entropy, color="skyblue")
    # 这里也可以用格式化数值元组显示，如果需要可以修改
    add_labels(ax, bars)
    plt.xlabel("加密算法")
    plt.ylabel("信息熵（bits/char）")
    plt.title("固定明文加密后密文的平均信息熵")
    plt.tight_layout()
    plt.show()

def run_tests():
    print("======== 加密算法性能与安全性评估（10轮 + 固定明文碰撞） ========")
    results = {}
    for algo in ["RSA", "ElGamal", "ECC"]:
        results[algo] = evaluate_algorithm(algo, rounds=10, fixed_plaintext_repeat=20)

    plot_results(results)

    def print_sorted(title, key):
        sorted_algos = sorted(results.items(), key=lambda x: x[1][key])
        print(f"\n【{title}】")
        for algo, metrics in sorted_algos:
            print(f"{algo}: {metrics[key]:.6f} 秒")

    print("\n============ 各时间对比 ============")
    print_sorted("密钥生成时间", "keygen")
    print_sorted("加密时间", "enc")
    print_sorted("解密时间", "dec")

    print("\n======== 信息熵对比（越高越强） ========")
    for algo in results:
        print(f"{algo}: {results[algo]['entropy']:.4f} ± {results[algo]['entropy_std']:.4f} bits/char")

    print("\n======== 碰撞测试结果 ========")
    for algo in results:
        print(f"{algo} 固定明文碰撞次数: {results[algo]['fixed_plaintext_collision']}")

if __name__ == "__main__":
    run_tests()
