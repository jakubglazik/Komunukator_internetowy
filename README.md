<h2>Projekt zaliczeniowy z przedmiotu Sieci Komputerowe 2</h2>. <p>Prosty komunikator internetowy umożliwiający użytkownikom rejestrację, logowanie oraz komunikację w czasie rzeczywistym. Aplikacja obsługuje zarówno rozmowy indywidualne, jak i grupowe. Użytkownicy mogą dodawać znajomych, wysyłać i odbierać zaproszenia do znajomych, a także tworzyć grupy do wspólnych rozmów.
Dane o użytkownikach zapisywane są w dedykownym pliku users,json umieszczonym na serwerze.</p>

<p>Autorzy: Jakub Glazik 156018, Kacper Szymański 155860</p>

<p>Plik serwera należy kompilować poprzez wywołanie komendy "g++ -pthread -Wall server.cpp -o nazwa_serwera.out", a następnie uruchamić aplikacje poprzez komendę: ./nazwa_serwera.out numer_portu<br>
Uruchomienie pliku klienta: python3 client.py adres_serwera numrt_portu</p>
