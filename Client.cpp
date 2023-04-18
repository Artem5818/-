/**
 * @file Client.cpp
 * @brief Файл взаимодействие с сервером
 */

#include "md5.h"
#include "Client.h"

/**
* @brief Взаимодействие с сервером
* @param str1 адрес сервера
* @param str2 порт сервера
* @throw client_error класс вызываемый при возникновении ошибки
*/

int Client::Server(string str1, string str2)
{
    //Проверка на введенный порт, если порт не введен выводится, то вводится значение по умолчанию
    if(str2 == "") {
        str2 = "33333";
    }

    //Проверка на введенный файл аунтификанции, если файл аунтификанции не введен выводится, то вводится значение по умолчанию
    if(autf_file == "") {
        autf_file = "./config/vclient.conf";
    }

    // Открытие файла для аутентификация
    ifstream fautf(autf_file); //fautf объект класса ifstream связан с файлом autf_file

    //2ошибки
    if(!fautf.is_open()) {
        throw client_error(string("fun:Server, param:autf_file.\nОшибка отрытия файла для аутентификация!"));
    }
    if(fautf.peek() == EOF) {
        fautf.close();
        throw client_error(string("fun:Server, param:autf_file.\nФайл для аутентификация пуст!"));
    }

    //Считывание логина и пароля
    getline(fautf, line); //Считывает строку из файла в line
    int k = line.find(" "); //Подсчет символов до пробела
    username = line.substr(0, k); //Возвращает подстроку данной строки начиная с начала строки и до кол-ва сиволов до пробела k
    pswd = line.erase(0, k+1); //Удаляет логин который считан выше виесте с пробелом и заносит остаток строки в пароль

    // Открытие файла для чтения векторов
    ifstream fvector(vector_file); //fautf объект класса ifstream связан с файлом vector_file

    //2 ошибки
    if(!fvector.is_open()) {
        fvector.close();
        throw client_error(string("fun:Server, param:vector_file.\nОшибка отрытия файла с векторами!"));
    }
    if(fvector.peek() == EOF) {
        fvector.close();
        throw client_error(string("fun:Server, param:vector_file.\nФайл с векторами пуст!"));
    }
    // Открытие файла для записи суммы
    ofstream fresultat(resultat_file); //fresultat объект класса ofstream связан с файлом resultat_file

    //Ошибка
    if(!fresultat.is_open()) {
        fresultat.close();
        throw client_error(string("fun:Server, param:resultat_file.\nОшибка отрытия файла для результатов!"));
    }
    //буфер для адреса
    char buf[255];

    try {
        //буфер для адреса
        strcpy(buf,str1.c_str());   //Функция strcpy() используется для копирования содержимого str1 в буфер, c_str формирует массив и возвращает указатель на него
    } catch (...) {
        throw client_error(std::string("fun:Server, param:buf.\nНе возможно получить адрес!"));
    }

    try {
        //Порт
        port = stoi(str2); // stoi из стринг в инт
    } catch (...) {
        throw client_error(string("fun:Server, param:port.\nНе возможно получить порт!"));
    }

    // структура с адресом нашей программы (клиента)
    sockaddr_in * selfAddr = new (sockaddr_in);
    selfAddr->sin_family = AF_INET; // интернет протокол IPv4
    selfAddr->sin_port = 0;         // любой порт на усмотрение ОС
    selfAddr->sin_addr.s_addr = 0; //  адрес

    // структура с адресом "на той стороне" (сервера)
    sockaddr_in * remoteAddr = new (sockaddr_in);
    remoteAddr->sin_family = AF_INET;  // интернет протокол IPv4
    remoteAddr->sin_port = htons(port); //Порт
    remoteAddr->sin_addr.s_addr = inet_addr(buf); // адрес

    // создаём сокет
    int mySocket = socket(AF_INET, SOCK_STREAM, 0); //tcp протокол
    if(mySocket == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:mySocket.\nОшибка создания сокета!"));
    }

    //связываем сокет с адрессом
    int rc = bind(mySocket,(const sockaddr *) selfAddr, sizeof(sockaddr_in));
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:selfAddr.\nОшибка привязки сокета с локальным адресом!"));
    }

    //установливаем соединение
    rc = connect(mySocket, (const sockaddr*) remoteAddr, sizeof(sockaddr_in));
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:remoteAddr.\nОшибка подключения сокета к удаленному серверу!"));
    }

    // буфер для передачи и приема данных
    char *buffer = new char[4096];
    strcpy(buffer,username.c_str()); //Функция strcpy() используется для копирования содержимого username в буфер, c_str формирует массив и возвращает указатель на него
    int msgLen = strlen(buffer);  //вычисляем длину строки

    // передаём сообщение из буффера
    rc = send(mySocket, buffer, msgLen, 0);
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:buffer.\nОшибка оправки логина!"));
    }
    cout << "Мы отправляем логин: " << buffer << endl;

    // принимаем ответ в буффер
    rc = recv(mySocket, buffer, 4096, 0);
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:buffer.\nОшибка получения ответа!"));
    }
    string s1 = string(buffer);
    buffer[rc] = '\0'; // конец принятой строки
    cout << "Мы получаем соль: " << buffer << endl; // вывод полученного сообщения от сервера

    // Вычисление хэша-кода от SALT+PASSWORD
    string hsh = s1 + pswd;
    msg = MD5_hash(hsh);

    // Отправка хэша от SALT+PASSWORD
    strcpy(buffer,msg.c_str());
    rc = send(mySocket, buffer, msg.length(), 0);
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:msg.\nОшибка оправки хэша!"));
    }
    cout << "Мы отправляем хэш: " << buffer << endl;

    // Получене ответа об аутентификации
    rc = recv(mySocket, buffer, sizeof(buffer), 0);
    buffer[rc] = '\0'; // конец принятой строки
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:buffer.\nОшибка получения ответа об аунтефикации!"));
    }
    cout << "Мы получаем ответ: " << buffer << endl; // вывод полученного сообщения от сервера

    uint32_t n;
    FILE *f;
    FILE *y; //описываем файловую переменную
//открываем существующий двоичный файл в режиме чтения
    const char *c = vector_file.c_str();
    f=fopen(c, "rb");
//считываем из файла одо целое число в переменную n
    fread(&n, sizeof(uint32_t), 1, f);
    rc = send(mySocket, &n, sizeof(n), 0);
    if (rc == -1) {
        close(mySocket);
        throw client_error(string("fun:Server, param:buffer.\nОшибка оправки кол-ва векторов!"));
    }
    cout << "Мы отправляем кол-во векторов: " << n << endl; // вывод полученного сообщения от сервера


    const char *h = resultat_file.c_str();
    y=fopen(h, "r+b");
    
    for(uint32_t i=0; i<n; i++) {
        uint32_t size;
        uint64_t d;
        fread(&size, sizeof(uint32_t), 1, f);
        uint32_t size1;
        size1=(4+size*sizeof(size));
        cout<<"Размер  "<<i+1<<"-го  вектора  "<<size1<<" байт"<<endl;
        rc = send(mySocket, &size, sizeof(size), 0);//отправка размера вектора
        if (rc == -1) {
            close(mySocket);
            throw client_error(string("fun:Server, param:buffer.\nОшибка оправки размера векторов!"));
        }

        uint64_t array[size]= {0};
        cout<<"Векторы в строке  ";
        for(uint32_t j=0; j<size; j++) {
            fread(&d, sizeof(uint64_t), 1, f);
            array[j]=d;                 //заполнение вектора в массив
            cout<<d<<" ";     //вывод вектора в строке
        }
        cout<<endl;
        send(mySocket, &array, sizeof(array), 0);
        if (rc == -1) {
            close(mySocket);
            throw client_error(string("fun:Server, param:buffer.\nОшибка оправки самих векторов!"));
        }
        cout << "Мы отправляем сам вектор: " << array << endl; // вывод полученного сообщения от сервера
        uint64_t sum = 0;
        rc = recv(mySocket, &sum, sizeof(sum), 0);
        if (rc == -1) {
            close(mySocket);
            throw client_error(string("fun:Server, param:buffer.\nОшибка получения ответа в виде суммы!"));
        }
        cout << "Мы получаем ответ: " << sum << endl; // вывод полученного сообщения от сервера
        fwrite(&sum, sizeof(uint64_t), 1, y);
    }

    // закрыем сокет
    close(mySocket);

    delete selfAddr;
    delete remoteAddr;
    delete[] buffer;
    return 0;
}
