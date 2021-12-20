# public-key-recovery-of-sm2
## 这是北京大学2021年秋季学期研究生课程密码学作业，实现sm2的公钥恢复  
sm2实现参考：https://github.com/gongxian-ding/gmssl-python
'''
def recover_Pulickey_SM2(self, v , Sign , data):

        r = int(Sign[0:self.para_len], 16)
        s = int(Sign[self.para_len:2*self.para_len], 16)
        e = int(data.hex(), 16)

        # x1 = (r - e) mod n if restrict x1 in [1, n-1]
        x = (r-e) % int(self.ecc_table['n'], base=16)

        # g = x1^3 + a*x1 + b (mod p)
        factor1 = ( x * x ) % int(self.ecc_table['p'], base=16)
        factor1 = ( factor1 * x ) % int(self.ecc_table['p'], base=16)
        factor2 = (x * int(self.ecc_table['a'], base=16) ) % int(self.ecc_table['p'], base=16)
        g = (factor1 + factor2)  % int(self.ecc_table['p'], base=16)
        g = ( g + int(self.ecc_table['b'], base=16) ) % int(self.ecc_table['p'], base=16)

        # U = (P - 3)/4 + 1;
        u = ( int(self.ecc_table['p'], base=16) - 3 ) // 4 + 1

        # y1 = g^u (mod p)
        y = self.cal_exp_mod( g, u, int(self.ecc_table['p'], base=16) )
        # y1^2 = g (mod p) 验证
        if( (y * y) % int(self.ecc_table['p'], base=16) != g ):
            return 'y1^2 = g (mod p) 验证失败'
        
        # 关于v，一般来说v只会有27或者28两种情况，标志着奇偶性
        v -=27
        if ( y&1 != v):
            y = int(self.ecc_table['p'], base=16) - y
        

        # 计算 g = -(s + r)^-1 (mod n)
        g = ( s + r ) % int(self.ecc_table['n'], base=16)
        g = int(self.ecc_table['n'], base=16) - self.cal_minus1_mod( g , int(self.ecc_table['n'], base=16) )

        # 计算Q= -Q = (x, -y)
        y = int(self.ecc_table['p'], base=16) - y
        form = '%%0%dx' % self.para_len
        form = form * 3
        Q =  form % (x, y, 1)
        # 计算s*G
        P = self._kg(s,self.ecc_table['g'])

        # -Q+s*G
        P = self._add_point(Q,P)

        # 雅各比坐标转仿射坐标
        P = self._convert_jacb_to_nor(P)

        # 计算点乘
        P = self._kg(g,P)

        return P
       
'''
