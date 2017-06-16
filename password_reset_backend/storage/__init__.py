import redis


class storage:
    __redisconnection = None

    def __init__(self, address, port, db=0):
        storage.__redisconnection = redis.StrictRedis(host=address, port=port, db=db, decode_responses=True)

    def get(key):
        return storage.__redisconnection.get(key)

    def getasstring(key):
        return storage.get(key) #.decode('utf-8')

    def getasint(key):
        return int(storage.get(key)) #.decode('utf-8'))

    def set(key, value):
        storage.__redisconnection.set(key, value)
        storage.save()

    def hget(key, field):
        return storage.__redisconnection.hget(key, field)

    def hgetall(key):
        return storage.__redisconnection.hgetall(key)

    def hgetasstring(key, field):
        return storage.hget(key, field)

    def hgetasint(key, field):
        return int(storage.hget(key, field)) #.decode('utf-8'))

    def hset(key, field, value):
        storage.__redisconnection.hset(key, field, value)
        storage.save()

    def hdel(key, field):
        storage.__redisconnection.hdel(key, field)
        storage.save()

    def lrange(key, start=0, end=65536):
        return storage.__redisconnection.lrange(key, start, end)
        storage.save()

    def delete(key):
        storage.__redisconnection.delete(key)
        storage.save()

    def lpush(key, value):
        storage.__redisconnection.lpush(key, value)
        storage.save()

    def sadd(key, value):
        storage.__redisconnection.sadd(key, value)
        storage.save()

    def smembers(key):
        return storage.__redisconnection.smembers(key)
        storage.save()

    def srem(key, value):
        storage.__redisconnection.srem(key, value)
        storage.save()

    def save():
        storage.__redisconnection.save()

    def keys(pattern):
        return storage.__redisconnection.keys(pattern)

    def expire(key, time):
        storage.__redisconnection.expire(key, time)