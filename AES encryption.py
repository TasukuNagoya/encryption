import base64
import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

st.set_page_config(page_title="AES 暗号化/復号ツール", layout="centered")

st.title("🔐 AES 暗号化 & 復号アプリケーション")
st.markdown("任意の鍵長、鍵テキスト、平文を入力して、AES-GCMによる暗号化・復号を行います。")

# 操作モードの選択
mode = st.radio("処理を選択してください", ["暗号化 (Encryption)", "復号 (Decryption)"], horizontal=True)


def adjust_key_length(key_text: str, required_bytes: int) -> bytes:
  """入力された鍵テキストを指定されたバイト数（AESは16, 24, 32バイト）に調整します"""
  key_bytes = key_text.encode("utf-8")
  if len(key_bytes) >= required_bytes:
    return key_bytes[:required_bytes]
  else:
    # 足りない場合はパディング（ゼロ埋め）
    return key_bytes.ljust(required_bytes, b"\0")


if mode == "暗号化 (Encryption)":
  st.subheader("📝 暗号化の設定")

  # 鍵長の選択 (AES-128: 16bytes, AES-192: 24bytes, AES-256: 32bytes)
  key_length_choice = st.selectbox(
      "鍵長 (Key Length)", [128, 192, 256], index=2  # デフォルトはAES-256
  )
  required_bytes = key_length_choice // 8

  key_input = st.text_input(
      "鍵テキスト (Key Text)",
      value="my-secret-key-12345",
      type="password",
      help=f"入力されたテキストから {required_bytes} バイトの鍵を生成します",
  )

  plaintext_input = st.text_area(
      "平文 (Plaintext)",
      value="ここに暗号化したい秘密のメッセージを入力してください。",
  )

  if st.button("暗号化を実行", type="primary"):
    if not key_input or not plaintext_input:
      st.warning("鍵と平文の両方を入力してください。")
    else:
      try:
        # 鍵の生成
        derived_key = adjust_key_length(key_input, required_bytes)

        # AESGCMの初期化
        aesgcm = AESGCM(derived_key)

        # GCMモードでは一意のナンス（Nonce / 初期化ベクトル）が必要
        # 12バイトのランダムなナンスを生成し、暗号文の先頭に付与するのが標準的
        import os

        nonce = os.urandom(12)

        # 暗号化の実行
        ciphertext = aesgcm.encrypt(nonce, plaintext_input.encode("utf-8"), None)

        # nonceと暗号文を結合してBase64エンコード（扱いやすくするため）
        encrypted_blob = nonce + ciphertext
        encoded_output = base64.b64encode(encrypted_blob).decode("utf-8")

        st.success("暗号化が完了しました！")
        st.text_area("暗号化結果 (Base64エンコード済)", value=encoded_output, height=100)
        st.info(
            "※ 復号する際はこの暗号化結果文字列と、同じ鍵テキスト・鍵長が必要になります。"
        )

      except Exception as e:
        st.error(f"エラーが発生しました: {e}")

else:
  st.subheader("🔓 復号の設定")

  key_length_choice = st.selectbox("使用した鍵長 (Key Length)", [128, 192, 256], index=2)
  required_bytes = key_length_choice // 8

  key_input = st.text_input(
      "鍵テキスト (Key Text)", value="my-secret-key-12345", type="password"
  )

  ciphertext_input = st.text_area(
      "暗号化されたテキスト (Base64)",
      placeholder="暗号化された文字列をここに貼り付けてください",
  )

  if st.button("復号を実行", type="primary"):
    if not key_input or not ciphertext_input:
      st.warning("鍵と暗号化テキストの両方を入力してください。")
    else:
      try:
        derived_key = adjust_key_length(key_input, required_bytes)
        aesgcm = AESGCM(derived_key)

        # Base64デコード
        encrypted_blob = base64.b64decode(ciphertext_input.encode("utf-8"))

        if len(encrypted_blob) < 12:
          st.error("無効な暗号化データです（データが短すぎます）。")
        else:
          # ナンス（最初の12バイト）と暗号文を分離
          nonce = encrypted_blob[:12]
          ciphertext = encrypted_blob[12:]

          # 復号の実行
          decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
          decrypted_text = decrypted_bytes.decode("utf-8")

          st.success("復号が成功しました！")
          st.text_area("復号された平文", value=decrypted_text, height=100)

      except Exception as e:
        st.error(
            f"復号に失敗しました。鍵、鍵長、または暗号化テキストが間違っている可能性があります: {e}"
        )