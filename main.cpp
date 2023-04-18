#include <UnitTest++/UnitTest++.h>
#include "Client.h"

using namespace std;

/*
 Для макроса TEST_FIXTURE можно объявить специальный класс, в конструкторе которого
будут выполняться действия, предваряющие тест, а в деструкторе — завершающие.
*/

struct Cons_fix {
    Client * p;
    Cons_fix()
    {
        p = new Client();
    }
    ~Cons_fix()
    {
        delete p;
    }
};

SUITE(Server)//Макрос. FIXTURE при одинаковых аргумиентах
{
    TEST_FIXTURE(Cons_fix, NormalTest) {
        //1 Удачный сценарий
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/config/vclient.conf";
        p->Server("127.0.0.1", "33333");
        CHECK(true);
    }

    TEST_FIXTURE(Cons_fix, ErrIp) {
        //2 Подключение к серверу. Введен не верный адрес
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/config/vclient.conf";
        CHECK_THROW(p->Server("2215024", "33333"), client_error);
    }



    TEST_FIXTURE(Cons_fix, ErrPort) {
        //3 Подключение к серверу. Введен не верный порт
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/config/vclient.conf";
        CHECK_THROW(p->Server("127.0.0.1", "3445"), client_error);
    }

    TEST_FIXTURE(Cons_fix, ErrPutyFileLogParol) {
        //4 Ошибка открытия файла с логинами и паролями
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "//home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/3/12235/config/vclient.conf";;
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }

    TEST_FIXTURE(Cons_fix, ErrPustoyFileLogParol) {
        //5 Ошибка чтения из файла с логинами и паролями
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/pustoy.txt";
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }

    TEST_FIXTURE(Cons_fix, ErrLogin) {
        //6 Ошибка идентификации. Введен не правильный логин
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/Nouser.conf";
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }

    TEST_FIXTURE(Cons_fix, ErrParol) {
        //7 Ошибка аутентификации. Введен не правильный пароль
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/NoPswd.conf";
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }

    TEST_FIXTURE(Cons_fix, ErrPutyFileVectors) {
        //8 Ошибка открытия файла с векторами
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/12432.txt";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/config/vclient.conf";
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }

    TEST_FIXTURE(Cons_fix, ErrPustoyFileVectors){
        //9 Ошибка чтения из файла с векторами
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/pustoy.txt";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/vclient.conf";
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }
    
        TEST_FIXTURE(Cons_fix, ErrPutyFileResultat) {
        //10 Ошибка открытия файла для записи суммы
        p->vector_file = "/home/stud/C++Projects/123144/build-Debug/bin/vector_64t.bin";
        p->resultat_file = "/home/stud/C++Projects/123144/build-Debug/bin/142235/resultat.bin";
        p->autf_file = "/home/stud/C++Projects/123144/build-Debug/bin/config/vclient.conf";
        CHECK_THROW(p->Server("127.0.0.1", "33333"), client_error);
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
