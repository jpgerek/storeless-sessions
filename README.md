# storeless-sessions

Class in php (>= 5.3) that implements a method to track user http sessions without the need of a data store using a user id a timestamp and signing them with a hash function in a cookie. It scales really well but sessions can not be destroyed they only get expired and therefore turn invalid.
