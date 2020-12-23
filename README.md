# AK_Lab7
Lab 7 Виконав: студент групи ІО-83, Тимочко Дмитро

Тема: модифікація реалізації лабораторної роботи 6.

Хід роботи:

1. Подивився адреси завантаження модулів, додатково ознайомився з debugfs.
2. Додав функцію bug_on() замість друку повідомлення, повернення einval для невалідного значення параметра.
3. Додав примусове внесення помилки у випадку коли функція kmalloc() повертає 0.
4. Модифікував makefile згідно поставленого завдання.
5. Виконав пошук місця аварії згідно до appendix1.

## Basic ##

### kmalloc повертає 0, помилка ###

![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_1.png)
![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_2.png)

### пошук помилки, при невалідному значення параметра ###

![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_3.png)
![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_4.png)

### запуск у дизасемблері ###

![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_5.png)
![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_6.png)
![Image alt](https://github.com/Dima2057/AK_Lab7/blob/master/images/Screenshot_7.png)
