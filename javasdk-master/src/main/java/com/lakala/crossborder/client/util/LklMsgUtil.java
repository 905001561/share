package com.lakala.crossborder.client.util;

import com.google.gson.Gson;
import com.lakala.crossborder.client.entities.LklCrossPayEncryptReq;
import com.lakala.crossborder.client.entities.LklCrossPayEncryptRes;
import com.lakala.crossborder.client.entities.LklCrossPaySuperReq;
import com.lakala.crossborder.client.entities.LklCrossPaySuperRes;
import com.lakala.crossborder.client.exception.LklEncryptException;
import com.lakala.crossborder.client.util.webhook.SuperWebHookRequest;
import com.lakala.crossborder.client.util.webhook.SuperWebHookResponse;

import java.io.UnsupportedEncodingException;

/**
 * <p>
 * 拉卡拉跨境支付消息工具类
 * tools for encrypt and decrypt msg
 * </p>
 *
 * @author jiangzhifei jiangzhifei@lakala.com
 */
public class LklMsgUtil {

	public static String Plat_Public_Key="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPg0O4rPQJL1O+jqJ4rBjFVNRAuDmBSoii9pYfPQBaescCVY0irkWWoLyfTT65TjvnPpOx+IfNzBTlB13qCEFm7algREoeUHjFgFNHiXJ2LK/R0+VWgXe5+EDFfbrFCPnmLKG3OcKDGQszP0VOf6VVTM1t56CpgaRMm1/+Tzd2TQIDAQAB";
    
	public static String Rsa_Pri_Key="MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIIca5rVVkBv8w0yjBna0E9YzKZhkM3acbACp34FYwkMbbx81aS2FLh+r8YPFQ03oWkSKVHXfXF5QrIDyWYABQHZmVUofG+o4eNPy27c+mAVCU1nY52iiz45WqxR9A50bRF1syPXk7UinuquIk0nd/uKbFz3emDKF7rG8d5Jzzz/AgMBAAECgYAgR/TaoXuY2S2wZI4mDAgK57k+vo4yxLPYO5Baz/NWV2MSlNZc22Agti3eMffDI75EV2ExEQnqkW9ew1nAmNik1if/Kywy3CEqEQeOmAcemTBxTk0xRU4lEDT7lVpVDUwq/V476O+UOI8FiG0VwZOH53QOfryOfZ/CUJKlSIBbYQJBAMD8MQ2XdXi+kr67lXEfOuDeQWIuhcY8Uwchrkwwo8TNzMHsl0DKSc0k9bGVruRioaAAQ3bmf/ckiAJuai6t+r0CQQCsmIXbnOZogGwtyQGrf5lT7GitwantUjgd2VWF9B9vTcWnedLSLoqhkGgd0p0mSGbnpuOc/rrw1Ba84NGTpDBrAkEAvXdbWXK3nCHNxIA6CeOVVKwgGRp/r84N3dSNYLPoNRGv0zxKiwuPRV7h8MV5/TNwZrubgKJwQ92Twn9QtB+PKQJAVfj/rH5CU0mtGT1oBIph0OkQ14SBZYKwC0ZIEJqi0emWjC7lseaXDZWGF1zjBL/J6pg6BujoK7Apx1nhaz69EwJBAKjtzGpEuVqNpLxwuby/2jTKomwN9PvdjZwMouA/fjgESzp0zaAaluN/ZtwDxE+dped4EV7RgjdB1XVHx3tzWw4=";

	public static String Taccountid="DOPCHN000500";
	/**
     * <p>
     * 加密请求参数
     * encrypt the msg sent to lakala.the des key is stored in threadlocal, which means if u want to get the right des key to decrypt lakala msg ,
     * u should guarantee the thread is the same  to the one used to send the request msg.Otherwise u should not store the des key to threadlocal
     * </p>
     *
     * @param obj      参数对象
     * @param dataHead 报文头
     * @param <T>
     * @return LklCrossPayEncryptReq 返回一个加密后的请求参数，用于向拉卡拉跨境支付平台发起请求
     * @throws LklEncryptException
     */
    public static <T> LklCrossPayEncryptReq encryptMsg(T obj, LklCrossPaySuperReq dataHead) throws LklEncryptException {
        ToolsUtil.remove();
        Plat_Public_Key=dataHead.getPlatPublicKey()==null?Plat_Public_Key:dataHead.getPlatPublicKey();
        String publicKey = Plat_Public_Key; 
        //LklCrossPayEnv.getEnvConfig().getPublicKey();
        Rsa_Pri_Key=dataHead.getRsaPriKey()==null?Rsa_Pri_Key:dataHead.getRsaPriKey();
        String privateKey =Rsa_Pri_Key;        		//LklCrossPayEnv.getEnvConfig().getPrivateKey();
        Taccountid=dataHead.getTaccountid()==null?Taccountid:dataHead.getTaccountid();
        String merId = Taccountid;
        		//LklCrossPayEnv.getEnvConfig().getMerId();
        String ts = dataHead.getTs();
        String ver = dataHead.getVer();

        //生成32位随机串
        //generate des key ,length is 32.the key is used to encrypt the biz data
        String secKey = ToolsUtil.getMerKey();
        //时间戳拼接对称密钥的hex，用响应方公钥加密，生成加密密钥密文，hex编码,生成encKey
        //the unencrypted enckey string =timestamp(yyyyMMddHHmmssssssss.refer to DateUtil.getCurrentTime())+des key
        String encKeyStr = ts + secKey;
        String encKey = null;
        try {
            //encrypted encKey
            encKey = ByteArrayUtil.byteArray2HexString(RSAUtil.encryptByPublicKey(encKeyStr.getBytes("GBK"), publicKey));
        } catch (Exception e) {
            throw new LklEncryptException("生成encKey失败", e);
        }
        Gson json = new Gson();
        String bizJson = json.toJson(obj);
        //生成encData
        String encData;
        try {
            if ("3.0.0".equals(ver.trim())) {
                //use seckey to encrypt the biz data
                encData = ByteArrayUtil.byteArray2HexString(AESCrypto.encrypt(bizJson, secKey));
            } else {
                //use seckey to encrypt the biz data
                encData = ByteArrayUtil.byteArray2HexString(DESCrypto.enCrypto(bizJson.getBytes("GBK"), secKey));
            }
        } catch (UnsupportedEncodingException e) {
            throw new LklEncryptException("加密业务参数失败", e);
        }


        //the unencrypted mac string
        String macStr = null;
        if ("1.0.0".equals(ver.trim())) {
            String reqType = dataHead.getReqType();
            String payTypeId = dataHead.getPayTypeId();
            if (null == payTypeId || "".equals(payTypeId)) {
                macStr = merId + ver + ts + reqType + encData + "";
            } else {
                macStr = merId + ver + ts + reqType + encData + payTypeId;
            }
        } else if ("2.0.0".equals(ver.trim()) || "3.0.0".equals(ver.trim())) {
            macStr = merId + ver + ts + encData;
        }
        //first encrypt mac with sha
        if ("3.0.0".equals(ver.trim())) {
            macStr = DigestUtil.Encrypt(macStr, "SHA-256");
        } else {
            macStr = DigestUtil.Encrypt(macStr, "SHA-1");
        }
        //生成MAC
        String mac = null;
        try {
            //finally encrypt mac with rsa,
            mac = ByteArrayUtil.byteArray2HexString(RSAUtil.encryptByPrivateKey(macStr.getBytes("GBK"), privateKey));
        } catch (Exception e) {
            throw new LklEncryptException(e);
        }

        //组装加密请求参数
        LklCrossPayEncryptReq req = new LklCrossPayEncryptReq();
        req.setMerId(merId);
        req.setPayTypeId(dataHead.getPayTypeId());
        req.setVer(dataHead.getVer());
        req.setTs(dataHead.getTs());
        req.setEncData(encData);
        req.setEncKey(encKey);
        req.setMac(mac);
        req.setReqType(dataHead.getReqType());

        return req;
    }

    /**
     * <p>
     * 解密拉卡拉响应报文
     * decrypt the response msg back from lakala.the des key should be the same to which used to encrypt the msg sent to lakala
     * </p>
     *
     * @param encryptRes 拉卡拉加密响应报文
     * @param <T>        拉卡拉接口业务参数,扩展自父类LklCrossPaySuperRes {@link LklCrossPaySuperRes}
     * @return
     * @throws LklEncryptException
     */
    public static <T extends LklCrossPaySuperRes> T decrypt(LklCrossPayEncryptRes encryptRes, Class<T> resClazz) throws LklEncryptException {
        T result = null;
        String retCode = encryptRes.getRetCode();
        String retMsg = encryptRes.getRetMsg();
        String merId = encryptRes.getMerId();
        String ver = encryptRes.getVer();
        String ts = encryptRes.getTs();
        String encData = encryptRes.getEncData();
        String reqType = encryptRes.getReqType();
        String payTypeId = encryptRes.getPayTypeId();
        //first get mac from the respinse msg
        String mac = encryptRes.getMac();
        //本地mac sha1字符串
        //your local mac string
        String retMacStr = null;
        //请求参数mac解密字符串sha1
        String reqMacStr = null;
        if ("1.0.0".equals(ver.trim())) {
            if (null == payTypeId || "".equals(payTypeId.trim())) {
                retMacStr = DigestUtil.Encrypt(retCode + retMsg + merId + ver + ts + reqType + encData + "", "SHA-1");
            } else {
                retMacStr = DigestUtil.Encrypt(retCode + retMsg + merId + ver + ts + reqType + encData + payTypeId, "SHA-1");
            }
        } else if ("2.0.0".equals(ver.trim())) {
            retMacStr = DigestUtil.Encrypt(retCode + retMsg + merId + ver + ts + encData, "SHA-1");
        } else if ("3.0.0".equals(ver.trim())) {
            retMacStr = DigestUtil.Encrypt(retCode + retMsg + merId + ver + ts + encData, "SHA-256");
        }
        try {
            //then generate ur local encrypted mac string
            reqMacStr = new String(RSAUtil.decryptByPublicKey(ByteArrayUtil.hexString2ByteArray(mac), Plat_Public_Key));//LklCrossPayEnv.getEnvConfig().getPublicKey()
        } catch (Exception e) {
            throw new LklEncryptException("mac解密失败", e);
        }
        //比较报文中mac sha1与本地mac sha是否相等
        //see if ur local mac is the same to mac from lakala
        if (!reqMacStr.equals(retMacStr)) {
            throw new LklEncryptException("mac校验失败");
        }
        //解密业务参数
        //get des key from threadlocal.
        String key = ToolsUtil.getMerKey();
        String requestData = null;

        //decrypt response msg from lakala
        try {
            if ("3.0.0".equals(ver.trim())) {
                requestData = new String(AESCrypto.decrypt(ByteArrayUtil.hexString2ByteArray(encData), key), "GBK");
            } else {
                requestData = new String(DESCrypto.deCrypt(ByteArrayUtil.hexString2ByteArray(encData), key), "GBK");
            }
        } catch (UnsupportedEncodingException e) {
            throw new LklEncryptException("业务参数解密失败", e);
        }

        Gson json = new Gson();
        result = json.fromJson(requestData, resClazz);
        ToolsUtil.remove();
        return result;
    }


    /**
     * 解密拉卡拉回调消息.
     * <b>ver=3.0.0的回调消息中会ver这个字段，其他则没有</b>
     * decrypt the webhook msg from lakala,des key should  get from the method :getMerchantKey
     *
     * @param lklCrossPayEncryptReq
     * @param resClazz
     * @param <T>
     * @return
     */
    public static <T extends SuperWebHookRequest> T decryptMsgFromLkl(LklCrossPayEncryptReq lklCrossPayEncryptReq, Class<T> resClazz) {
        T result = null;
        String ts = lklCrossPayEncryptReq.getTs();
        String encData = lklCrossPayEncryptReq.getEncData();
        String reqType = lklCrossPayEncryptReq.getReqType();
        String ver = lklCrossPayEncryptReq.getVer();
        //encrypted mac string from lakala
        String mac = lklCrossPayEncryptReq.getMac();

        //请求参数mac解密字符串sha1
        //your local mac string
        String reqMacStr = null;
        //本地mac sha1字符串
        String retMacStr = DigestUtil.Encrypt(ts + reqType + encData + "", "SHA-1");
        if ("3.0.0".equals(ver.trim())) {
            retMacStr = DigestUtil.Encrypt(ts + reqType + encData + "", "SHA-256");
        }
        try {
            reqMacStr = new String(RSAUtil.decryptByPublicKey(ByteArrayUtil.hexString2ByteArray(mac), Plat_Public_Key));
        } catch (Exception e) {
            throw new LklEncryptException("mac解密失败", e);
        }
        if (!retMacStr.equals(reqMacStr)) {
            throw new LklEncryptException("mac校验失败");
        }
        //用响应方私钥解密加密密钥密文，比对时间戳，取后32个字符反HEX，得对称密钥
        //get encKey from the web hook msg
        String encKey = lklCrossPayEncryptReq.getEncKey();
        //get des key from the enckey
        String desKey = getMerchantKey(encKey, Rsa_Pri_Key);
        ToolsUtil.remove();
        // if u guarantee the thread is the same  to the one used to send the web hook response msg then u can store the key in threadlocal.Otherwise u should not store the des key to threadlocal
        //store des key ,when u send response msg ,u can use it
        ToolsUtil.setMerKey(desKey);
        //用获得的对称密钥解密加密业务参数
        String requestData = null;
        try {
            //decrypt biz data with key
            if ("3.0.0".equals(ver.trim())) {
                requestData = new String(AESCrypto.decrypt(ByteArrayUtil.hexString2ByteArray(encData), desKey), "GBK");
            } else {
                requestData = new String(DESCrypto.deCrypt(ByteArrayUtil.hexString2ByteArray(encData), desKey), "GBK");
            }

        } catch (UnsupportedEncodingException e) {
            throw new LklEncryptException("业务参数解密失败", e);
        }
        Gson json = new Gson();
        result = json.fromJson(requestData, resClazz);
        return result;

    }

    /**
     * 加密拉卡拉webhook响应返回给拉卡拉
     * encrypt the webhook response msg sent back to lakala
     *
     * @param webHookResponse
     * @return
     */
    public static LklCrossPayEncryptRes encryptWebHookMsg(SuperWebHookResponse webHookResponse, LklCrossPayEncryptRes encryptRes) {
        String publicKey = Plat_Public_Key;
        String privateKey = Rsa_Pri_Key;

        String retCode = encryptRes.getRetCode();
        String retMsg = encryptRes.getRetMsg();
        String ts = encryptRes.getTs();
        String ver = encryptRes.getVer();
        //get seckey from threadlocal
        String secKey = ToolsUtil.getMerKey();
        //unencrypted  enc key string
//        String encKeyStr = ts + secKey;
//        String encKey = null;
//        try {
//            //encrypt enc key string
//            encKey = ByteArrayUtil.byteArray2HexString(RSAUtil.encryptByPublicKey(encKeyStr.getBytes("GBK"), publicKey));
//        } catch (Exception e) {
//            throw new LklEncryptException("生成encKey失败", e);
//        }
        Gson json = new Gson();

        //生成encData
        String encData = "";
        try {
            String bizJson = json.toJson(webHookResponse);
            //encrypt biz data with the des key
            if ("3.0.0".equals(ver.trim())) {
                encData = ByteArrayUtil.byteArray2HexString(AESCrypto.encrypt(bizJson, secKey));
            } else {
                encData = ByteArrayUtil.byteArray2HexString(DESCrypto.enCrypto(bizJson.getBytes("GBK"), secKey));
            }

        } catch (UnsupportedEncodingException e) {
            throw new LklEncryptException("加密业务参数失败", e);
        }
        String reqType = encryptRes.getReqType();
        //generate mac string
        String macStr = null;
        //SHA
        if ("3.0.0".equals(ver.trim())) {
            macStr = retCode + retMsg + ts + reqType;
            macStr = DigestUtil.Encrypt(macStr, "SHA-256");
        } else {
            macStr = ts + reqType + encData;
            macStr = DigestUtil.Encrypt(macStr, "SHA-1");
        }
        //生成MAC
        String mac = null;
        try {
            //encryot mac string
            mac = ByteArrayUtil.byteArray2HexString(RSAUtil.encryptByPrivateKey(macStr.getBytes("GBK"), privateKey));
        } catch (Exception e) {
            throw new LklEncryptException(e);
        }
        encryptRes.setMac(mac);
//        encryptRes.setEncKey(encKey);
        encryptRes.setEncData(encData);
        ToolsUtil.remove();
        return encryptRes;
    }


    /**
     * 计算请求方对称密钥
     *
     * @param reqEncKey  加密密钥encKey
     * @param privateKey 私钥
     * @return
     */
    private final static String getMerchantKey(String reqEncKey, String privateKey) {

        if (reqEncKey == null || privateKey == null) return null;
        // 用响应方私钥解密加密密钥密文，比对时间戳，取后32个字符反HEX，得对称密钥
        String merKey = ""; // 商户对称密钥
        try {
            merKey = new String(RSAUtil.decryptByPrivateKey(ByteArrayUtil.hexString2ByteArray(reqEncKey), privateKey), "GBK");
        } catch (Exception e) {
            throw new LklEncryptException("解密请求方对称密钥失败", e);
        }
        return merKey.substring(merKey.length() - 32, merKey.length());
    }
    
    
    public static <T extends SuperWebHookRequest> T decryptMsgFromLklCustomAuth(LklCrossPayEncryptReq lklCrossPayEncryptReq, Class<T> resClazz) {
        T result = null;
        String ts = lklCrossPayEncryptReq.getTs();
        String encData = lklCrossPayEncryptReq.getEncData();
        String reqType = lklCrossPayEncryptReq.getReqType();
        String ver = lklCrossPayEncryptReq.getVer();
        //encrypted mac string from lakala
        String mac = lklCrossPayEncryptReq.getMac();
        String merId=lklCrossPayEncryptReq.getMerId();
        //请求参数mac解密字符串sha1
        //your local mac string
        String reqMacStr = null;
        String retMacStr=null;
        //本地mac sha1字符串
        String macStr=merId + ver + ts + encData;
        if ("3.0.0".equals(ver.trim())) {
        	retMacStr= DigestUtil.Encrypt(macStr, "SHA-256");
        }
        try {
            reqMacStr = new String(RSAUtil.decryptByPublicKey(ByteArrayUtil.hexString2ByteArray(mac), Plat_Public_Key));
        } catch (Exception e) {
            throw new LklEncryptException("mac解密失败", e);
        }
        if (!retMacStr.equals(reqMacStr)) {
            throw new LklEncryptException("mac校验失败");
        }
        //用响应方私钥解密加密密钥密文，比对时间戳，取后32个字符反HEX，得对称密钥
        //get encKey from the web hook msg
        String encKey = lklCrossPayEncryptReq.getEncKey();
        //get des key from the enckey
        String desKey = getMerchantKey(encKey, Rsa_Pri_Key);
        ToolsUtil.remove();
        // if u guarantee the thread is the same  to the one used to send the web hook response msg then u can store the key in threadlocal.Otherwise u should not store the des key to threadlocal
        //store des key ,when u send response msg ,u can use it
        ToolsUtil.setMerKey(desKey);
        //用获得的对称密钥解密加密业务参数
        String requestData = null;
        try {
            //decrypt biz data with key
            if ("3.0.0".equals(ver.trim())) {
                requestData = new String(AESCrypto.decrypt(ByteArrayUtil.hexString2ByteArray(encData), desKey), "GBK");
            } else {
                requestData = new String(DESCrypto.deCrypt(ByteArrayUtil.hexString2ByteArray(encData), desKey), "GBK");
            }

        } catch (UnsupportedEncodingException e) {
            throw new LklEncryptException("业务参数解密失败", e);
        }
        Gson json = new Gson();
        result = json.fromJson(requestData, resClazz);
        return result;

    }
    
    public static LklCrossPayEncryptRes encryptWebHookMsgCustomAuth(SuperWebHookResponse webHookResponse, LklCrossPayEncryptRes encryptRes) {
        String publicKey = Plat_Public_Key;
        String privateKey = Rsa_Pri_Key;

        String retCode = encryptRes.getRetCode();
        String retMsg = encryptRes.getRetMsg();
        String ts = encryptRes.getTs();
        String ver = encryptRes.getVer();
        String merId=encryptRes.getMerId();
        //get seckey from threadlocal
        String secKey = encryptRes.getEncKey();
        //unencrypted  enc key string
//        String encKeyStr = ts + secKey;
//        String encKey = null;
//        try {
//            //encrypt enc key string
//            encKey = ByteArrayUtil.byteArray2HexString(RSAUtil.encryptByPublicKey(encKeyStr.getBytes("GBK"), publicKey));
//        } catch (Exception e) {
//            throw new LklEncryptException("生成encKey失败", e);
//        }
        Gson json = new Gson();

        //生成encData
        String encData = "";
        try {
            String bizJson = json.toJson(webHookResponse);
            //encrypt biz data with the des key
            if ("3.0.0".equals(ver.trim())) {
                encData = ByteArrayUtil.byteArray2HexString(AESCrypto.encrypt(bizJson, secKey));
            } else {
                encData = ByteArrayUtil.byteArray2HexString(DESCrypto.enCrypto(bizJson.getBytes("GBK"), secKey));
            }

        } catch (UnsupportedEncodingException e) {
            throw new LklEncryptException("加密业务参数失败", e);
        }
        String reqType = encryptRes.getReqType();
        //generate mac string
        String macStr = null;
        //SHA
        if ("3.0.0".equals(ver.trim())) {
            macStr = retCode+retMsg+merId + ver+ts + encData;
            macStr = DigestUtil.Encrypt(macStr, "SHA-256");
        } 
        //生成MAC
        String mac = null;
        try {
            //encryot mac string
            mac = ByteArrayUtil.byteArray2HexString(RSAUtil.encryptByPrivateKey(macStr.getBytes("GBK"), privateKey));
        } catch (Exception e) {
            throw new LklEncryptException(e);
        }
        encryptRes.setMac(mac);
//        encryptRes.setEncKey(encKey);
        encryptRes.setEncData(encData);
        ToolsUtil.remove();
        return encryptRes;
    }

}
