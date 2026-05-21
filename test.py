import asyncio
from goygram import GoyGram, filters
import logging

logging.basicConfig(level=logging.DEBUG)
API_ID = 31228640
API_HASH = "6b96981510216203ccf9c6e499ce8827"

app = GoyGram(
    api_id=API_ID, 
    api_hash=API_HASH, 
    session_name="my_account"
)

@app.on_cmd(".ping")
async def ping_handler(msg):
    await msg.reply("<b>🏓 PONG!</b> GoyGram Userbot is running on <i>Rust core</i>. ⚡", parse_mode="HTML")

@app.on_cmd(".del")
async def delete_msg(msg):
    await msg.delete()

@app.on_cmd(".chats")
async def get_my_chats(msg):
    dialogs = await app.mt_get_dialogs(limit=5)
    chat_list = "<b>📋 Последние 5 чатов:</b>\n"
    for d in dialogs:
        title = d.get('title', str(d.get('id', '?')))
        chat_list += f"— {title}\n"
    await msg.reply(chat_list, parse_mode="HTML")

@app.on_msg(filt=filters.text & filters.me)
async def self_logger(msg):
    if msg.text.lower() == "тест":
        await app.edit_message_text(
            chat_id=msg.chat_id,
            message_id=msg.msg_id,
            text="✅ Тест пройден успешно!"
        )

if __name__ == "__main__":
    print("Запуск юзербота... Следуйте инструкциям в терминале.")
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass
