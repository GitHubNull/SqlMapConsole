package utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;

public class SerializeUtil {
    /**
     * 字节数组转换为字符串
     */
    public static String bytesToString(byte[] bytes) {
        return org.apache.commons.codec.binary.Hex.encodeHexString(bytes);
//        return org.apache.commons.codec.binary.Base64.encodeBase64String(bytes);
    }

    /**
     * 字符串转换为字节数组
     *
     * @param str 入参字符串
     * @return 转换之后的字节数组
     */
    public static byte[] stringToByte(String str) throws DecoderException {
        return org.apache.commons.codec.binary.Hex.decodeHex(str);
//        return org.apache.commons.codec.binary.Base64.decodeBase64(str);
    }

    /**
     * 序列化对象（依赖commons-lang3包）
     *
     * @param obj 序列化对象
     * @return 对象序列化之后的字符串
     */
    public static String serialize(Serializable obj) {
        if (obj != null) {
            byte[] bytes = SerializationUtils.serialize(obj);
            return bytesToString(bytes);
        }
        return null;
    }

    /**
     * 反序列化对象（依赖commons-lang3包）
     *
     * @param str 反序列化字符串
     * @return 反序列化之后的对象
     */
    public static <T extends Serializable> T deserialize(String str) throws Exception {
        if (StringUtils.isNotEmpty(str)) {
            return SerializationUtils.deserialize(stringToByte(str));
        }
        return null;
    }
}
