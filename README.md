# CMDlist
Аналог CMD Helper'a от Гонщика, с возможностью добавления собственных команд и описаний к ним, возможность добавить команды всех скриптов/плагинов с помощью консоли(chatcmds).

Активация: По умолчанию активировано при открытии чата, /cmdlist - активация/деактивация , ЛКМ - ввести команду, ПКМ - ввести команду в окно ввода, СКМ по команде - изменить команду/добавить описание команде из консоли. СКМ по тексту названия списка - выполнить сортировку.

Настройка: возле первого "+" есть чекбокс, он отвечает за возможность перемещения окна с командами. Остальное интуитивно понятно или смотрите видео. Вне игры команды можно добавить через CMDlist.json в папке config.

Требования: MoonLoader 0.26, mimgui (+ lfs и ziplib, для проверки и установки mimgui)

Установка: .lua в moonloader.

Если вы не хотите проверку установлена ли библиотека mimgui удалите строку 955 и строки с 972 до конца
