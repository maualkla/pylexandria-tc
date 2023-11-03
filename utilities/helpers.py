import os, base64

class Helpers:
    ## return String (lenght)
    def randomString(_length):
        try:
            print(" >> helpers.randomString() helper.")
            import random, string
            output_str = ''.join(random.choice(string.ascii_letters) for i in range(_length))
            return output_str
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## return userId
    def idGenerator(_length):
        try:
            print(" >> idGenerator() helper.")
            userId = Helpers.currentDate()
            userId = Helpers.randomString(2) + userId + Helpers.randomString(_length)
            return userId
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Transaction Number Generator
    def trxGenerator(_date, _user):
        try:
            print(" >> trxGenerator() helper.")
            from datetime import datetime
            _now = datetime.now()
            _dateGen = _now.strftime("%d%m%YH%M%S")
            _trxId = Helpers.randomString(2) + _dateGen + Helpers.randomString(20)
            _trx_obj = {
                "date" : _date,
                "user" : _user,
                "id": _trxId
            }
            ### Por el momento no crearemos la trx por que antes necesitamos helpers para:
            ## - Eliminar trx por usuario.
            ## - eliminar trx por fecha
            ## - eliminar todas las transacciones.
            ## @TODO
            """
            if trx_ref.document(_trxId).set(_trx_obj):
                return _trxId
            else: 
                return False
            """
            return _trxId
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}
        
    ## Base64 encode
    def b64Encode(_string):
        try:
            print(" >> b64Encode() helper.")
            _out = base64.b64encode(_string.encode('utf-8'))
            _r_out = str(_out, "utf-8")
            return _r_out
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Base64 decode
    def b64Decode(_string):
        try:
            print(" >> b64Decode() helper.")
            _out = base64.b64decode(_string).decode('utf-8')
            return _out
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Current date: 
    def currentDate():
        try:
            print(" >> currrentDate() helper.")
            from datetime import datetime
            _now = datetime.now()
            _now = _now.strftime("%d%m%YH%M%S")
            return _now
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}
        
    ## Get URL parameters:
    ## Function receive a string like this "limit:10;username:maualkla;active:true"
    ## Has to return a dict containing {"parameter" : "value"}
    def splitParams(_query):
        try:
            print(" >> splitParams() helper.")
            print(_query)
            print(_query.count(":"))
            print(_query.count(";"))
            if int(_query.count(":")) == int(_query.count(";"))+1:
                _x = 0
                _params_in_query = _query.count(":")
                _response = {}
                print(1)
                while _x < _params_in_query:
                    print(2)
                    _index = _query.find(";")
                    print(3)
                    if _index == -1: 
                        print(3.1)
                        _temp = _query[0:]
                    else: 
                        print (3.2)
                        _temp = _query[0:_index]
                    _index_2 = _temp.find(":")
                    print(4)
                    _response[_temp[0:_index_2]] = _temp[_index_2+1:]
                    print(5)
                    _query = _query[_index+1:]
                    print(5)
                    _x += 1
                return _response
            else:
                print(1.1)
                return {"status":"params_query_not_valid"}
        except Exception as e:
            print(" (!) Exception in splitParameters(): ")
            print(str(e))
            return False