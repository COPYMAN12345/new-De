// Generate key from password and salt
function generateKey(password, salt) {
    return crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    ).then(key => {
        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            key,
            { name: "AES-CBC", length: 256 },
            true,
            ["decrypt"]
        );
    });
}

// Decrypt the message
async function decryptMessage(encryptedMessage, password) {
    try {
        // Convert Base64 encoded message to Uint8Array
        const data = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));

        // Extract salt, IV, and encrypted data
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 32);
        const encryptedData = data.slice(32);

        // Generate key
        const key = await generateKey(password, salt);

        // Decrypt the data
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv },
            key,
            encryptedData
        );

        // Decode the decrypted message
        const decryptedMessage = new TextDecoder().decode(decrypted);

        // Split the decrypted message into timestamp, time limit, and message
        const [timestampStr, timeLimitStr, message] = decryptedMessage.split(":", 3);

        // Validate the timestamp
        const timestamp = parseInt(timestampStr, 10);
        const timeLimitMinutes = parseInt(timeLimitStr, 10);
        const currentTime = Math.floor(Date.now() / 1000);

        if (currentTime - timestamp > timeLimitMinutes * 60) {
            throw new Error("The message is older than the specified time limit and is no longer valid.");
        }

        // Return the decrypted message
        return message;
    } catch (error) {
        console.error("Decryption failed:", error);
        throw new Error("Decryption failed. The message may be invalid or expired.");
    }
}

// Decrypt button event listener
document.getElementById("decryptBtn").addEventListener("click", async () => {
    const encryptedMessage = document.getElementById("encryptedMessage").value;
    const password = document.getElementById("password").value;

    if (!encryptedMessage || !password) {
        alert("Please fill in all fields.");
        return;
    }

    try {
        const decryptedMessage = await decryptMessage(encryptedMessage, password);
        document.getElementById("decryptedMessage").value = decryptedMessage;
    } catch (error) {
        console.error("Decryption failed:", error);
        alert("Decryption failed. The message may be invalid or expired.");
    }
});

// QR Code Scanner Logic
const video = document.getElementById("qr-video");
const scanBtn = document.getElementById("scan-btn");
const fileInput = document.getElementById("file-input");
const uploadBtn = document.getElementById("upload-btn");

// Scan QR Code from Camera
scanBtn.addEventListener("click", () => {
    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })
        .then(stream => {
            video.srcObject = stream;
            video.play();
            requestAnimationFrame(scanQR);
        })
        .catch(err => {
            console.error("Error accessing the camera: ", err);
            alert("Error accessing the camera. Please ensure you have granted camera permissions.");
        });
});

// Function to scan QR code from video stream
function scanQR() {
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        const canvas = document.createElement("canvas");
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const context = canvas.getContext("2d");
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code) {
            document.getElementById("encryptedMessage").value = code.data;
            video.srcObject.getTracks().forEach(track => track.stop());
        } else {
            requestAnimationFrame(scanQR);
        }
    } else {
        requestAnimationFrame(scanQR);
    }
}

// Scan QR Code from File
uploadBtn.addEventListener("click", () => {
    fileInput.click(); // Trigger the file input dialog
});

fileInput.addEventListener("change", (event) => {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.src = e.target.result;
            img.onload = () => {
                const canvas = document.createElement("canvas");
                canvas.width = img.width;
                canvas.height = img.height;
                const context = canvas.getContext("2d");
                context.drawImage(img, 0, 0, canvas.width, canvas.height);
                const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);

                if (code) {
                    document.getElementById("encryptedMessage").value = code.data;
                } else {
                    alert("No QR code found in the uploaded image.");
                }
            };
        };
        reader.readAsDataURL(file);
    }
});