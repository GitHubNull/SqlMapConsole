package utils;

import burp.BurpExtender;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static utils.GlobalStaticsVar.TMP_REQUEST_FILE_DIR_PATH;

public class TmpRequestFileHelper {

    public static File getFileByPath(String filePath) {
        return StringUtils.isBlank(filePath) ? null : new File(filePath);
    }

    public static String genTmpFileFinalPath() {
        String tmpFileName = String.format("tmp-%s.txt", MyStringUtil.getDateTimeStr(1));

        String tempDirectoryPath = null;

        if (Files.isDirectory(new File(TMP_REQUEST_FILE_DIR_PATH).toPath())) {
            tempDirectoryPath = TMP_REQUEST_FILE_DIR_PATH;
        } else {

            tempDirectoryPath = FileUtils.getTempDirectory().getAbsolutePath();
        }

        tempDirectoryPath = tempDirectoryPath.replace("\\", "/");

        if (tempDirectoryPath.endsWith("\\") || tempDirectoryPath.endsWith("/")) {
            tempDirectoryPath = tempDirectoryPath.substring(0, tempDirectoryPath.length() - 1);
        }


//        final String finalTmpFileName = String.format("%s/%s", tempDirectoryPath, tmpFileName);
        return String.format("%s/%s", tempDirectoryPath, tmpFileName);
    }

    public static String writeStringToFile(String text) {
        File tmpFile = new File(genTmpFileFinalPath());

        try {
            FileUtils.writeStringToFile(tmpFile, text,
                    StandardCharsets.UTF_8.name());
        } catch (IOException ioException) {
            BurpExtender.stderr.println(ioException.getMessage());
            return null;
        }

        return tmpFile.getAbsolutePath();
    }


    public static String writeBytesToFile(byte[] textBytes) {
        File tmpFile = new File(genTmpFileFinalPath());

        try {
            FileUtils.writeByteArrayToFile(tmpFile, textBytes);
        } catch (IOException ioException) {
            BurpExtender.stderr.println(ioException.getMessage());
            return null;
        }

        return tmpFile.getAbsolutePath();
    }
}
