package com.eazybytes.constant;

public final class ApplicationConstants {

    public static final String JWT_SECRET_KEY = "JWT_SECRET";

    public static final String JWT_SECRET_DEFAULT_VALUE = "aP98WZQtnYvH4vFiw3kM5th7XoFVF5DkNvAfNhtrPTM=";
    //Do not expose this JWT_SECRET_KEY or JWT_SECRET_DEFAULT_VALUE in production grade applications

    public static final String JWT_HEADER = "Authorization";

    private ApplicationConstants(){}
}
