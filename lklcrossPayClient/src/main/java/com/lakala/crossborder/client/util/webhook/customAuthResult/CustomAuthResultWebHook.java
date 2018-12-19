package com.lakala.crossborder.client.util.webhook.customAuthResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.lakala.crossborder.client.entities.LklCrossPayEncryptReq;
import com.lakala.crossborder.client.entities.LklCrossPayEncryptRes;
import com.lakala.crossborder.client.entities.webHook.CustomAuthNotify;
import com.lakala.crossborder.client.entities.webHook.CustomAuthResultNotifyRes;
import com.lakala.crossborder.client.enums.LklEnv;
import com.lakala.crossborder.client.exception.LklCommonException;
import com.lakala.crossborder.client.exception.LklEncryptException;
import com.lakala.crossborder.client.util.LklCrossPayEnv;
import com.lakala.crossborder.client.util.LklMsgUtil;
import com.lakala.crossborder.client.util.webhook.LklWebHookIntf;
import com.lakala.crossborder.client.util.webhook.WebHookHandler;

@RestController
public class CustomAuthResultWebHook {

	private static final Logger logger = LoggerFactory.getLogger(CustomAuthResultWebHook .class);
    
    @Autowired
    private LklCrossPayEnv lklCrossPayEnv;
    
    @RequestMapping(value = "lklCustomAuthResult/handle")
	public LklCrossPayEncryptRes proceed(@RequestBody LklCrossPayEncryptReq notify) {
        //注册应用环境
        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPg0O4rPQJL1O+jqJ4rBjFVNRAuDmBSoii9pYfPQBaescCVY0irkWWoLyfTT65TjvnPpOx+IfNzBTlB13qCEFm7algREoeUHjFgFNHiXJ2LK/R0+VWgXe5+EDFfbrFCPnmLKG3OcKDGQszP0VOf6VVTM1t56CpgaRMm1/+Tzd2TQIDAQAB";
        String privKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMOaT/7ybPWEi9Cagf0XX0+vkcf/ypUjJ3AgMNo9uAJGj5PRgf8C21QM1FH5x2c7wdvcuziqm8NnOsQzapZqHVV0e0uPLly3DXg5VfptfouyJmuWaGzrTyk03yoKBXGP/0J0cLBD+YXqdGTKen9k48cL0YPO/IW2rY1RoqIvnxLjAgMBAAECgYA9UOJCyTveuu4ZNlYJQIpgMGlCiKy4k4yJWY322+IS1Iutir91cS/P6TWlfOdFNTZP9aG64cByQKnrVzLSc/E9i+N+GiLg28Lvm0XPrTBC68YtTY7tpWGHwsq4diYeWhBga1tYeVtJhsVSh/3DgiwlM8r6XOrMl75I/420/9XOAQJBAO/n1dkLnuxuv739cfmvCrlhofvkD/iOCFkHpmIbfqz2z9ijgy931f0C7+EmdvI+Cl8TzZl5kShs9p8K1swPOtUCQQDQuZ2dzKxDZSiN0gQ6ZAnLMof2RwPF56TK3SfugtCXfCeyLzjI5Vb60Nei8cvWiiGPbi7u3ibEWOdF2VUwYwLXAkB1agbsmlZmqvFnAALnS7c48cLAsGbspD8Lq8XP4FsINieVhLlw4vq1QNm8XQH8H0ceL2gBxFC581Jkln54EsAdAkBorr9bVjyLbJ/DSTKvql6zF7vTC9jbmAsxZ2vQlrFRWIZ8OmzLbSKLltSft4+ZIRwl2IgXazmcPk533MF6DB5vAkB+oyOxUWmkhJ0jBeIFsuYUrwa/yvOL0r1QUXkh4r/JBcMol4QL5RwzJ07KBLpUOTMCOizG5G16kovpEpeneDfq";
        lklCrossPayEnv.registerEnv(LklEnv.LIVE, "DOPCHN000696", privKey, pubKey);
    	logger.debug("entering method proceed,req={}", notify.toString());
    	 CustomAuthNotify customAuthNotify = null;
         LklCrossPayEncryptRes res = new LklCrossPayEncryptRes();
         res.setMerId(notify.getMerId());
         res.setTs(notify.getTs());
         res.setRetMsg("通知成功");
         res.setRetCode("0000");
         res.setVer("3.0.0");
         res.setEncKey(notify.getEncKey());

         try {
        	 customAuthNotify= LklMsgUtil.decryptMsgFromLklCustomAuth(notify, CustomAuthNotify.class);
            // 得到通知的结果进行业务处理
             CustomAuthResultNotifyRes response = new CustomAuthResultNotifyRes();
             response.setAmount(customAuthNotify.getAmount());
             response.setBgUrl(customAuthNotify.getBgUrl());
             response.setBizTypeCode(customAuthNotify.getBizTypeCode());
             response.setCbpName(customAuthNotify.getCbpName());
             response.setClientId(customAuthNotify.getClientId());
             response.setCuId(customAuthNotify.getCuId());
             response.setCustomcomCode(customAuthNotify.getCustomcomCode());
             response.setGoodsFee(customAuthNotify.getGoodsFee());
             response.setMobile(customAuthNotify.getMobile());
             response.setName(customAuthNotify.getName());
             response.setOrderNo(customAuthNotify.getOrderNo());
             response.setOrderNote(customAuthNotify.getOrderNote());
             response.setPayerMail(customAuthNotify.getPayerMail());
             response.setPayOrderId(customAuthNotify.getPayOrderId());
             response.setTaxFee(customAuthNotify.getTaxFee());
             res = LklMsgUtil.encryptWebHookMsgCustomAuth(response, res);
         } catch (LklCommonException e) {
             logger.error("lakala custom auth error", e);
             res.setRetCode("9999");
             res.setRetMsg(e.getMessage());
         } catch (LklEncryptException e) {
             logger.error("lakala custom auth error", e);
             res.setRetCode("9999");
             res.setRetMsg(e.getMessage());
         } catch (Exception e) {
             logger.error("lakala custom auth error", e);
             res.setRetCode("9999");
             res.setRetMsg("系统异常");
         }
         logger.debug("exiting method proceed,res ={}", res.toString());
         return res;
	}

}
