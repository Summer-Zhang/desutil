/**
 * qjbaoxian.com Inc.
 * Copyright (C) 2016-2018 All Rights Reserved.
 */
package com.qjbx.util;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author summer
 * @version $Id SecurityUtils.java, v 0.1 2018-12-11 下午5:51 summer Exp $$
 */
public class SecurityUtils {


  public static final String DEFAULT_TRIPPLE_DES_KEY = "MATRIX_@)!*WMYQCD!";

  // 算法名称
  private static final String KEY_ALGORITHM = "desede";
  // 算法名称/加密模式/填充方式
  private static final String CIPHER_ALGORITHM = "desede/CBC/PKCS7Padding";

  private static final byte[] KEY_IV = {1, 2, 3, 4, 5, 9, 7, 8};//初始化向量

  private static final String DEFAULT_ENCODING = "UTF-8";

  /**
   * CBC加密
   *
   * @param key 密钥
   * @param keyIV IV
   * @param data 明文
   * @return Base64编码的密文
   * @throws Exception
   */
  private static byte[] des3EncodeCBC(String key, byte[] keyIV, String data) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    Key desKey = keyGenerator(key);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    IvParameterSpec ips = new IvParameterSpec(keyIV);
    cipher.init(Cipher.ENCRYPT_MODE, desKey, ips);
    return cipher.doFinal(data.getBytes(DEFAULT_ENCODING));
  }

  /**
   * CBC加密
   *
   * @param key 密钥
   * @param data 明文
   * @return Base64编码的密文
   * @throws Exception
   */
  public static String des3EncodeCBC(String key, String data)  {
    byte[] result = new byte[0];
    try {
      result = des3EncodeCBC(key, KEY_IV, data);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return new String(Base64.encode(result));
  }

  /**
   * 生成密钥key对象
   *
   * @param keyStr 密钥字符串
   * @return 密钥对象
   * @throws Exception
   */
  private static Key keyGenerator(String keyStr) throws Exception {
    byte[] input = get3DesKey(keyStr);
    DESedeKeySpec KeySpec = new DESedeKeySpec(input);
    SecretKeyFactory KeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
    return ((Key) (KeyFactory.generateSecret(((java.security.spec.KeySpec) (KeySpec)))));
  }

  private static int parse(char c) {
    if (c >= 'a') {
      return (c - 'a' + 10) & 0x0f;
    }
    if (c >= 'A') {
      return (c - 'A' + 10) & 0x0f;
    }
    return (c - '0') & 0x0f;
  }

  // 从十六进制字符串到字节数组转换
  static byte[] HexString2Bytes(String hexStr) {
    byte[] b = new byte[hexStr.length() / 2];
    int j = 0;
    for (int i = 0; i < b.length; i++) {
      char c0 = hexStr.charAt(j++);
      char c1 = hexStr.charAt(j++);
      b[i] = (byte) ((parse(c0) << 4) | parse(c1));
    }
    return b;
  }

  /**
   * 生成24字节的3DES密钥。
   * （不够24字节，则补0；超过24字节，则取前24字节。）
   *
   * @param key 密钥字符串
   * @return
   */
  static byte[] get3DesKey(String key) {
    byte[] keyBytes = new byte[24];
    byte[] originalBytes = key.getBytes(Charset.forName(DEFAULT_ENCODING));
    if (key.getBytes().length > 24) {
      System.arraycopy(originalBytes, 0, keyBytes, 0, 24);
    } else {
      for (int i = 0; i < 24; i++) {
        if (i < key.getBytes().length) {
          keyBytes[i] = originalBytes[i];
        } else {
          keyBytes[i] = 0x00;
        }
      }
    }
    return keyBytes;
  }

  /**
   * CBC解密
   *
   * @param key 密钥
   * @param data Base64编码的密文
   * @return 明文
   * @throws Exception
   */
  public static String des3DecodeCBC(String key, String data) {
    byte[] result = new byte[0];
    try {
      result = des3DecodeCBC(key, KEY_IV, Base64.decode(data));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return new String(result);
  }

  /**
   * CBC解密
   *
   * @param key 密钥
   * @param keyiv IV
   * @param data Base64编码的密文
   * @return 明文
   * @throws Exception
   */
  private static byte[] des3DecodeCBC(String key, byte[] keyiv, byte[] data) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    Key desKey = keyGenerator(key);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    IvParameterSpec ips = new IvParameterSpec(keyiv);
    cipher.init(Cipher.DECRYPT_MODE, desKey, ips);
    return cipher.doFinal(data);
  }

  public static void main(String[] args) {
    try {
      String res = SecurityUtils.des3EncodeCBC
          (DEFAULT_TRIPPLE_DES_KEY, "1000000020164475");
      System.out.println(res);
      String origin = SecurityUtils.des3DecodeCBC(DEFAULT_TRIPPLE_DES_KEY, res);
      System.out.println(origin);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
