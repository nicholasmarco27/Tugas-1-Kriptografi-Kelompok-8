from flask import Flask, render_template, request
import base64

app = Flask(__name__)

def xor_encrypt(plain_text, key):
    # XOR encryption
    cipher_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(plain_text, key))
    return cipher_text

def shift_bits(text):
    # Geser 1 bit ke kiri
    return ''.join(chr((ord(c) << 1) & 0xFF) for c in text)

def repeat_key(key, length):
    return (key * (length // len(key))) + key[:length % len(key)]

def ecb_encrypt(plain_text, key):
    # Repeat the key if it's shorter than plaintext
    key = repeat_key(key, len(plain_text))

    # Encrypt without padding
    cipher_text = xor_encrypt(plain_text, key)
    shifted_text = shift_bits(cipher_text)
    return shifted_text

def xor_block(block, key):
    # XOR a block of text with the key
    return ''.join(chr(ord(b) ^ ord(k)) for b, k in zip(block, key))

def cbc_encrypt(plain_text, key, iv=None):
    block_size = len(key)

    # Set IV as binary 00000000 (8-bit), length should match the plain_text
    if iv is None:
        iv = chr(0) * block_size  # Default IV set to 00000000 (binary) with the length of the block size

    # Encrypt without padding
    cipher_text = ''
    prev_block = iv

    for i in range(0, len(plain_text), block_size):
        block = plain_text[i:i + block_size]
        if len(block) < block_size:
            block = block.ljust(block_size, '\0')  # Pad block if needed

        # XOR block with previous ciphertext (or IV for the first block)
        xored_block = xor_block(block, prev_block)

        # Encrypt with XOR (simple substitution for demonstration purposes)
        encrypted_block = xor_block(xored_block, key)

        # Shift bits after encryption
        shifted_block = shift_bits(encrypted_block)

        # Append to cipher text
        cipher_text += shifted_block

        # Update previous block
        prev_block = shifted_block

    return cipher_text

def to_hex(text):
    return ''.join(format(ord(c), '02x') for c in text)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        plain_text = request.form['plain_text']
        key = request.form['key']
        mode = request.form['mode']
        output_format = request.form['output_format']  # Get output format from form

        if mode == 'ECB':
            cipher_text = ecb_encrypt(plain_text, key)
        elif mode == 'CBC':
            cipher_text = cbc_encrypt(plain_text, key)
        else:
            cipher_text = "Mode tidak valid"

        # Convert output to either base64 or hex based on user choice
        if output_format == 'base64':
            encoded_cipher_text = base64.b64encode(cipher_text.encode()).decode()
        elif output_format == 'hex':
            encoded_cipher_text = to_hex(cipher_text)
        else:
            encoded_cipher_text = "Format output tidak valid"

        return render_template('index.html', cipher_text=encoded_cipher_text, plain_text=plain_text, key=key, mode=mode, output_format=output_format)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
