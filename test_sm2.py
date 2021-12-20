import sm2

def test_sm2():
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    data = b"this is a message!"
    print("-----------------test sign and verify---------------")
    random_hex_str = sm2.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(data, random_hex_str)
    print('sign:%s' % sign)
    verify = sm2_crypt.verify(sign, data)
    print('verify:%s' % verify)
    assert verify

    print("-----------------pubilic key recovery---------------")
    recover_public_key = sm2_crypt.recover_Pulickey_SM2( 28 , sign , data)
    print(recover_public_key)


if __name__ == '__main__':
    test_sm2()


