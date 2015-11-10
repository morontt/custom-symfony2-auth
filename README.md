Custom Symfony Auth
===================

Экспериментальный проект, задуманный для того, чтобы повозиться с кастомной
аутентификацией в [Symfony2](http://symfony.com/)

В качестве источника пользователей выступает файл */app/config/.users*, генерируемый утилитой
[*htpasswd*](http://httpd.apache.org/docs/2.2/programs/htpasswd.html), входящей в состав утилит веб-сервера *Apache2*.

Добавление пользователей в */app/config/.users*:

```bash
# Хеширование алгоритмом MD5(APR)
htpasswd -bm ./app/config/.users pupkin1 pa$$word

# хеширование SHA1
htpasswd -bs ./app/config/.users petya GOD

# хеширование CRYPT
htpasswd -bd ./app/config/.users vasya qwerty
```
