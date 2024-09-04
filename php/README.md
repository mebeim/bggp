# BGGP5 - @mebeim - PHP

Tested with PHP 7.4.33 and 8.3.9 inside Docker
(e.g. `docker run --rm -it php:8 bash`).

| File                     | Source size |
|:-------------------------|:------------|
| [`BGGP5.php`](BGGP5.php) | 26 bytes    |

Note that the file misses the final newline character. This is intended to save
space!

Needs `allow_url_include=1` and `short_open_tag=1` in `php.ini`. Needs to be
invoked with `/binary.golf/5/5` as the current working directory. Lame, I know,
but apparently still a valid BGGP entry!

```bash
echo 'allow_url_include=1' | sudo tee /usr/local/etc/php/php.ini
echo 'short_open_tag=1' | sudo tee -a /usr/local/etc/php/php.ini

sudo mkdir -p /binary.golf/5/5
sudo chown -R $USER:$USER /binary.golf

cp BGGP5.php /binary.golf/5/5
cd /binary.golf/5/5
php BGGP5.php
```

---

*Copyright &copy; 2024 Marco Bonelli (@mebeim). Licensed under the MIT License.*
