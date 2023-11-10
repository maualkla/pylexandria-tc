## utilities.helpers

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
            if int(_query.count(":")) == int(_query.count(";"))+1:
                _x = 0
                _params_in_query = _query.count(":")
                _response = {}
                while _x < _params_in_query:
                    _index = _query.find(";")
                    if _index == -1:
                        _temp = _query[0:]
                    else: 
                        _temp = _query[0:_index]
                    _index_2 = _temp.find(":")
                    _response[_temp[0:_index_2]] = _temp[_index_2+1:]
                    _query = _query[_index+1:]
                    _x += 1
                return _response
            else:
                return {"status":"params_query_not_valid"}
        except Exception as e:
            print(" (!) Exception in splitParameters(): ")
            print(str(e))
            return False