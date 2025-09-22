# password-vault

MVP реализации "современного хранилища паролей" — утилита командной строки, 
позволяющая создавать зашифрованный файл с паролями и управлять записями через
простые команды.

## Возможности

- Создание нового хранилища с мастер-паролем (`password-vault <файл> init`).
- Добавление, обновление и удаление записей с учётными данными.
- Получение списка записей и просмотр конкретных секретов.
- Шифрование записей при помощи Fernet (AES-128 + HMAC) с ключом, полученным
  из мастер-пароля через Scrypt.

## Установка

```bash
pip install .
```

Для разработки можно установить зависимости с поддержкой тестов:

```bash
pip install .[dev]
```

## Использование

```bash
# создать новое хранилище
password-vault vault.json init

# добавить запись
password-vault vault.json add email --username user@example.com --url https://mail.example.com

# показать запись
password-vault vault.json show email

# удалить запись
password-vault vault.json remove email
```

## Тесты

```bash
pytest
```
