package utils;

import burp.BurpExtender;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static utils.GlobalStaticsVar.TMP_REQUEST_FILE_DIR_PATH;

public class TmpRequestFileHelper {

    public static String genTmpFileFinalPath() {
        String tmpFileName = String.format("tmp-%s.txt", MyStringUtil.getDateTimeStr(1));

        String tempDirectoryPath;

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
