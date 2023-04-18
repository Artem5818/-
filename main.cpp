/**
* @file main.cpp
* @brief Главный модуль программы для получения параметров от пользователя
* @param opt переменная для работы с параметрами командной строки
* @param optarg переменная для получения парметров командной строки
*/

#include "Client.h"

using namespace std;

int main (int argc, char *argv[])
{

    Client Podclychenie;    //класс для пердачи айпи и порта в main

    //Параметры не заданны, выводится справка
    if(argc == 1) {
        cout << "!!!Программа клиента!!!" << endl;
        cout << "Прамметры для запуска клиента:" << endl;
        cout << "\t-h — справка" << endl;
        cout << "\t-i — адрес сервера (обязательный)" << endl;
        cout << "\t-p — порт сервера (необязательный — по умолчанию 33333)" << endl;
        cout << "\t-e — имя файла с исходными данными (обязательный)" << endl;
        cout << "\t-s — имя файла для сохранения результатов (обязательный)" << endl;
        cout << "\t-a — имя файла с ID и PASSWORD клиента (необязательный — по умолчанию 〜/.config/vclient.conf)" << endl;
        return 0;
    }

    string str1;//айпи
    string str2;//порт

    //Функция getopt последовательно перебирает переданные параметры в программу
    //optarg переменная для получения парметров командной строки
    //opt переменная для работы с параметрами командной строки
    int opt;
    while ((opt=getopt (argc,argv,"hi:p:e:s:a:"))!=-1) {

        switch(opt) {

        //Кейс справки
        case 'h':
            cout << "!!!Программа клиента!!!" << endl;
            cout << "Прамметры для запуска клиента:" << endl;
            cout << "\t-h — справка" << endl;
            cout << "\t-i — адрес сервера (обязательный)" << endl;
            cout << "\t-p — порт сервера (необязательный — по умолчанию 33333)" << endl;
            cout << "\t-e — имя файла с исходными данными (обязательный)" << endl;
            cout << "\t-s — имя файла для сохранения результатов (обязательный)" << endl;
            cout << "\t-a — имя файла с ID и PASSWORD клиента (необязательный — по умолчанию 〜/.config/vclient.conf)" << endl;
            return 0;

        //Кейс айпишника
        case 'i':
            str1 = argv[2];

            break;

        //Кейс порта
        case 'p':
                str2 = string(optarg);
            break;

        //Кейс файла с векторами
        case 'e':
            Podclychenie.vector_file = string(optarg);
            break;

        //Кейс файла с результатов
        case 's':
            Podclychenie.resultat_file = string(optarg);
            break;

        //Кейс файла с логином и паролем
        case 'a':
            Podclychenie.autf_file = string(optarg);
            break;

        //Кейс если параметры не заданы
        case '?':
            cout << "Праметр задан не верно или такого праметра не существует" << endl;
            return 0;
        };
    };

    Podclychenie.Server(str1, str2);
    return 0;
};
