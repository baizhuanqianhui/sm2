package sm4;

/**
 * Created by zhuxiaole on 2018/1/13.
 */
public class SM4_Context {
    public int mode;

    public long[] sk;

    public boolean isPadding;

    public SM4_Context()
    {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
