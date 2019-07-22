package com.qjbx;

import com.qjbx.util.SecurityUtils;

/**
 * Hello world!
 */
public class App {

  public static void main(String[] args) {
    String s = "hello";
    String encode = null;
    encode = SecurityUtils.des3EncodeCBC("MATRIX_@)!*WMYQCD!", s);
    System.out.println("encode" + encode);
  }
}
