document.addEventListener('DOMContentLoaded', function () {
    const toast = document.getElementById("toast");

    function showToast(message) {
        toast.innerText = message;
        toast.className = "show";
        setTimeout(() => {
            toast.className = toast.className.replace("show", "");
        }, 3000);
    }

    document.getElementById("generate-keys").addEventListener("click", async function () {
        const algo = document.getElementById("algorithm").value;
        const response = await fetch(`/generate_keys?algo=${algo}`);
        const data = await response.json();

        document.getElementById("public-key").value = data.public_key;
        document.getElementById("private-key").value = data.private_key;

        showToast("密钥生成成功！");
    });

    document.getElementById("encrypt-btn").addEventListener("click", async function () {
        const algo = document.getElementById("algorithm").value;
        const message = document.getElementById("plaintext").value;
        const publicKey = document.getElementById("public-key").value;

        const response = await fetch(`/encrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algo, message, public_key: publicKey })
        });

        const data = await response.json();
        document.getElementById("ciphertext").value = data.ciphertext;
        showToast("加密成功！");
    });

    document.getElementById("decrypt-btn").addEventListener("click", async function () {
        const algo = document.getElementById("algorithm").value;
        const ciphertext = document.getElementById("ciphertext").value;
        const privateKey = document.getElementById("private-key").value;

        const response = await fetch(`/decrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algo, ciphertext, private_key: privateKey })
        });

        const data = await response.json();
        document.getElementById("plaintext").value = data.plaintext;
        showToast("解密成功！");
    });

    // 复制功能
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const target = document.querySelector(`#${btn.dataset.target}`);
            target.select();
            document.execCommand("copy");
            showToast("已复制到剪贴板！");
        });
    });
});
