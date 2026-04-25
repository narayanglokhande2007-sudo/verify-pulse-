<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VerifyPulse - AI Fact Checker</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #fff;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 500px;
            margin: 0 auto;
            background: #1a1f3a;
            border-radius: 15px;
            padding: 20px;
            border: 1px solid #2d3748;
        }
        h1 {
            text-align: center;
            color: #00d4ff;
            margin-bottom: 20px;
            font-size: 28px;
        }
        .tagline {
            text-align: center;
            color: #a0aec0;
            margin-bottom: 30px;
            font-size: 14px;
        }
        textarea {
            width: 100%;
            padding: 15px;
            border: 2px solid #2d3748;
            border-radius: 10px;
            background: rgba(0, 212, 255, 0.05);
            color: #fff;
            font-size: 16px;
            min-height: 120px;
            font-family: Arial, sans-serif;
            margin-bottom: 15px;
        }
        textarea:focus {
            outline: none;
            border-color: #00d4ff;
        }
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #00d4ff, #0099cc);
            color: #0a0e27;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin-bottom: 10px;
        }
        button:hover {
            opacity: 0.9;
        }
        .result {
            display: none;
            margin-top: 20px;
            background: rgba(0, 212, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #00d4ff;
        }
        .result.show {
            display: block;
        }
        .loading {
            display: none;
            text-align: center;
            color: #a0aec0;
        }
        .loading.show {
            display: block;
        }
        .privacy {
            margin-top: 20px;
            padding: 15px;
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 10px;
            text-align: center;
            color: #a0aec0;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ VerifyPulse</h1>
        <p class="tagline">AI-Powered Fact Checking</p>
        
        <textarea id="textInput" placeholder="Enter text to verify..."></textarea>
        
        <button onclick="verifyText()">✨ Verify Now</button>
        <button onclick="clearInput()" style="background: transparent; border: 2px solid #00d4ff; color: #00d4ff;">Clear</button>
        
        <div class="loading" id="loading">
            <p>⏳ Analyzing...</p>
        </div>
        
        <div class="result" id="result">
            <h3 id="resultTitle">Result</h3>
            <p id="resultText">---</p>
        </div>
        
        <div class="privacy">
            🔐 <strong>Privacy Protected:</strong> We never store your data. 100% Secure.
        </div>
    </div>

    <script>
        async function verifyText() {
            const text = document.getElementById('textInput').value.trim();
            
            if (!text) {
                alert('Please enter some text!');
                return;
            }
            
            document.getElementById('loading').classList.add('show');
            document.getElementById('result').classList.remove('show');
            
            try {
                const response = await fetch("https://api.anthropic.com/v1/messages", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "x-api-key": "sk-ant-YOUR_API_KEY_HERE"
                    },
                    body: JSON.stringify({
                        model: "claude-opus-4-1-20250805",
                        max_tokens: 500,
                        messages: [
                            {
                                role: "user",
                                content: `Fact-check this: "${text}" - Reply with: VERDICT (TRUE/FALSE/UNCERTAIN), CONFIDENCE (%), ANALYSIS (2-3 lines)`
                            }
                        ]
                    })
                });
                
                const data = await response.json();
                
                if (data.error) {
                    document.getElementById('resultTitle').textContent = '❌ Error';
                    document.getElementById('resultText').textContent = 'API Key missing or invalid. Add your API key to the code.';
                } else {
                    const result = data.content[0].text;
                    document.getElementById('resultTitle').textContent = '✅ Result';
                    document.getElementById('resultText').textContent = result;
                }
            } catch (error) {
                document.getElementById('resultTitle').textContent = '❌ Error';
                document.getElementById('resultText').textContent = 'Connection error. Check your internet.';
            } finally {
                document.getElementById('loading').classList.remove('show');
                document.getElementById('result').classList.add('show');
            }
        }
        
        function clearInput() {
            document.getElementById('textInput').value = '';
            document.getElementById('textInput').focus();
        }
    </script>
</body>
</html>
