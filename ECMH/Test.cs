using System.Security.Cryptography;
using Xunit;

namespace ECMH;

public class MultiSetTests
{
    private static readonly byte[] D1_BYTES = Convert.FromHexString("982051FD1E4BA744BBBE680E1FEE14677BA1A3C3540BF7B1CDB606E857233E0E00000000010000000100F2052A0100000043410496B538E853519C726A2C91E61EC11600AE1390813A627C66FB8BE7947BE63C52DA7589379515D4E0A604F8141781E62294721166BF621E73A82CBF2342C858EEAC");

    private static readonly byte[] D2_BYTES = Convert.FromHexString("D5FDCC541E25DE1C7A5ADDEDF24858B8BB665C9F36EF744EE42C316022C90F9B00000000020000000100F2052A010000004341047211A824F55B505228E4C3D5194C1FCFAA15A456ABDF37F9B9D97A4040AFC073DEE6C89064984F03385237D92167C13E236446B417AB79A0FCAE412AE3316B77AC");

    private static readonly byte[] D3_BYTES = Convert.FromHexString("44F672226090D85DB9A9F2FBFE5F0F9609B387AF7BE5B7FBB7A1767C831C9E9900000000030000000100F2052A0100000043410494B9D3E76C5B1629ECF97FFF95D7A4BBDAC87CC26099ADA28066C6FF1EB9191223CD897194A08D0C2726C5747F1DB49E8CF90E75DC3E3550AE9B30086F3CD5AAAC");

    private static readonly byte[] EMPTY_HASH = new byte[32];

    private static byte[] HashBytes(byte[] bytes)
    {
        return SHA256.HashData(bytes);
    }

    [Fact]
    public void Empty()
    {
        var mset = new MultiSet();
        Assert.Equal(EMPTY_HASH, mset.GetHash());
    }

    [Fact]
    public void EmptyAdd()
    {
        var mset = new MultiSet();
        var mset2 = new MultiSet();

        mset.AddSet(mset2);

        Assert.Equal(EMPTY_HASH, mset.GetHash());
    }

    [Fact]
    public void D1()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D1_BYTES));

        const string expected = "F883195933A687170C34FA1ADEC66FE2861889279FB12C03A3FB0CA68AD87893";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D2()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D2_BYTES));

        const string expected = "EF85D123A15DA95D8AFF92623AD1E1C9FCDA3BAA801BD40BC567A83A6FDCF3E2";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D3()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D3_BYTES));

        const string expected = "CFADF40FC017FAFF5E04CCC0A2FAE0FD616E4226DD7C03B1334A7A610468EDFF";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D1_MS_Plus_D2_MS()
    {
        var mset1 = new MultiSet();
        mset1.AddItem(HashBytes(D1_BYTES));

        var mset2 = new MultiSet();
        mset2.AddItem(HashBytes(D2_BYTES));

        mset1.AddSet(mset2);

        const string expected = "FABAFD38D07370982A34547DAF5B57B8A4398696D6FD2294788ABDA07B1FAAAF";
        Assert.Equal(expected, mset1.GetHashHex());
    }

    [Fact]
    public void D1_Plus_D2()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D1_BYTES));
        mset.AddItem(HashBytes(D2_BYTES));

        const string expected = "FABAFD38D07370982A34547DAF5B57B8A4398696D6FD2294788ABDA07B1FAAAF";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D1_MS_Plus_D2_MS_Plus_D3_MS()
    {
        var mset1 = new MultiSet();
        mset1.AddItem(HashBytes(D1_BYTES));

        var mset2 = new MultiSet();
        mset2.AddItem(HashBytes(D2_BYTES));

        var mset3 = new MultiSet();
        mset3.AddItem(HashBytes(D3_BYTES));

        mset1.AddSet(mset2);
        mset1.AddSet(mset3);

        const string expected = "1CBCCDA23D7CE8C5A8B008008E1738E6BF9CFFB1D5B86A92A4E62B5394A636E2";
        Assert.Equal(expected, mset1.GetHashHex());
    }

    [Fact]
    public void D1_Plus_D2_Plus_D3()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D1_BYTES));
        mset.AddItem(HashBytes(D2_BYTES));
        mset.AddItem(HashBytes(D3_BYTES));

        const string expected = "1CBCCDA23D7CE8C5A8B008008E1738E6BF9CFFB1D5B86A92A4E62B5394A636E2";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D1_Plus_D2_Plus_D3_Minus_D3()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D1_BYTES));
        mset.AddItem(HashBytes(D2_BYTES));
        mset.AddItem(HashBytes(D3_BYTES));
        mset.RemoveItem(HashBytes(D3_BYTES));

        const string expected = "FABAFD38D07370982A34547DAF5B57B8A4398696D6FD2294788ABDA07B1FAAAF";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D1_Plus_D2_Plus_D3_MS_Minus_D2_Plus_D3_MS()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D1_BYTES));
        mset.AddItem(HashBytes(D2_BYTES));
        mset.AddItem(HashBytes(D3_BYTES));

        var mset2 = new MultiSet();
        mset2.AddItem(HashBytes(D2_BYTES));
        mset2.AddItem(HashBytes(D3_BYTES));

        mset.RemoveSet(mset2);

        const string expected = "F883195933A687170C34FA1ADEC66FE2861889279FB12C03A3FB0CA68AD87893";
        Assert.Equal(expected, mset.GetHashHex());
    }

    [Fact]
    public void D2_Plus_D1_Plus_D3_Order_Does_Not_Matter()
    {
        var mset = new MultiSet();
        mset.AddItem(HashBytes(D2_BYTES));
        mset.AddItem(HashBytes(D1_BYTES));
        mset.AddItem(HashBytes(D3_BYTES));

        const string expected = "1CBCCDA23D7CE8C5A8B008008E1738E6BF9CFFB1D5B86A92A4E62B5394A636E2";
        Assert.Equal(expected, mset.GetHashHex());
    }
}