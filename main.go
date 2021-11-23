package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-flac/flacpicture"
	"github.com/go-flac/flacvorbis"
	"github.com/go-flac/go-flac"

	"github.com/bogem/id3v2"
)

//
var (
	aesCoreKey   = []byte{0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57}
	aesModifyKey = []byte{0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28}
)

type MetaInfo struct {
	MusicID       int             `json:"musicId"`
	MusicName     string          `json:"musicName"`
	Artist        [][]interface{} `json:"artist"` // [[string,int],]
	AlbumID       int             `json:"albumId"`
	Album         string          `json:"album"`
	AlbumPicDocID interface{}     `json:"albumPicDocId"` // string or int
	AlbumPic      string          `json:"albumPic"`
	BitRate       int             `json:"bitrate"`
	Mp3DocID      string          `json:"mp3DocId"`
	Duration      int             `json:"duration"`
	MvID          int             `json:"mvId"`
	Alias         []string        `json:"alias"`
	TransNames    []interface{}   `json:"transNames"`
	Format        string          `json:"format"`
}

func buildKeyBox(key []byte) []byte {
	box := make([]byte, 256)
	for i := 0; i < 256; i++ {
		box[i] = byte(i)
	}
	keyLen := byte(len(key))
	var c, lastByte, keyOffset byte
	for i := 0; i < 256; i++ {
		c = (box[i] + lastByte + key[keyOffset]) & 0xff
		keyOffset++
		if keyOffset >= keyLen {
			keyOffset = 0
		}
		box[i], box[c] = box[c], box[i]
		lastByte = c
	}
	return box
}

func fixBlockSize(src []byte) []byte {
	return src[:len(src)/aes.BlockSize*aes.BlockSize]
}

func containPNGHeader(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	return string(data[:8]) == string([]byte{137, 80, 78, 71, 13, 10, 26, 10})
}

func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func decryptAes128Ecb(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	dataLen := len(data)
	decrypted := make([]byte, dataLen)
	bs := block.BlockSize()
	for i := 0; i <= dataLen-bs; i += bs {
		block.Decrypt(decrypted[i:i+bs], data[i:i+bs])
	}
	return PKCS7UnPadding(decrypted), nil
}

func readUint32(rBuf []byte, fp *os.File) uint32 {
	_, err := fp.Read(rBuf)
	checkError(err)
	return binary.LittleEndian.Uint32(rBuf)
}

func checkError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func DecodeNCM(name string) bool {
	fp, err := os.Open(name)
	if err != nil {
		log.Println(err)
		return false
	}
	defer fp.Close()

	var rBuf = make([]byte, 4)
	uLen := readUint32(rBuf, fp)

	if uLen != 0x4e455443 {
		log.Println("not netease cryptoed file")
		return false
	}

	uLen = readUint32(rBuf, fp)
	if uLen != 0x4d414446 {
		log.Println("not netease cryptoed file")
		return false
	}

	fp.Seek(2, 1)
	uLen = readUint32(rBuf, fp)

	var keyData = make([]byte, uLen)
	_, err = fp.Read(keyData)
	checkError(err)

	for i := range keyData {
		keyData[i] ^= 0x64
	}

	deKeyData, err := decryptAes128Ecb(aesCoreKey, fixBlockSize(keyData))
	checkError(err)

	// 17 = len("neteasecloudmusic")
	deKeyData = deKeyData[17:]

	uLen = readUint32(rBuf, fp)
	var modifyData = make([]byte, uLen)
	_, err = fp.Read(modifyData)
	checkError(err)

	for i := range modifyData {
		modifyData[i] ^= 0x63
	}
	deModifyData := make([]byte, base64.StdEncoding.DecodedLen(len(modifyData)-22))
	_, err = base64.StdEncoding.Decode(deModifyData, modifyData[22:])
	checkError(err)

	deData, err := decryptAes128Ecb(aesModifyKey, fixBlockSize(deModifyData))
	checkError(err)

	// 6 = len("music:")
	deData = deData[6:]

	var meta MetaInfo
	err = json.Unmarshal(deData, &meta)
	checkError(err)

	// crc32 check
	fp.Seek(4, 1)
	fp.Seek(5, 1)

	imgLen := readUint32(rBuf, fp)

	imgData := func() []byte {
		if imgLen > 0 {
			data := make([]byte, imgLen)
			_, err = fp.Read(data)
			checkError(err)
			return data
		}
		return nil
	}()

	box := buildKeyBox(deKeyData)
	n := 0x8000

	outfile := strings.Replace(name, ".ncm", "."+meta.Format, -1)

	fpOut, err := os.OpenFile(outfile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	checkError(err)

	var tb = make([]byte, n)
	for {
		_, err := fp.Read(tb)
		if err == io.EOF { // read EOF
			break
		} else if err != nil {
			log.Println(err)
			fpOut.Close()
			return false
		}
		for i := 0; i < n; i++ {
			j := byte((i + 1) & 0xff)
			tb[i] ^= box[(box[j]+box[(box[j]+j)&0xff])&0xff]
		}
		_, err = fpOut.Write(tb)
		if err != nil {
			log.Println(err)
			fpOut.Close()
			return false
		}
	}
	fpOut.Close()

	// log.Println(outfile)
	switch meta.Format {
	case "mp3":
		addMP3Tag(outfile, imgData, &meta)
	case "flac":
		addFLACTag(outfile, imgData, &meta)
	}
	return true
}

func fetchUrl(url string) []byte {
	req, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte{}))
	if err != nil {
		log.Println(err)
		return nil
	}
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil
	}
	if res.StatusCode != http.StatusOK {
		log.Printf("Failed to download album pic: remote returned %d\n", res.StatusCode)
		return nil
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return nil
	}
	return data
}

func addFLACTag(fileName string, imgData []byte, meta *MetaInfo) {
	f, err := flac.ParseFile(fileName)
	if err != nil {
		log.Println(err)
		return
	}

	if imgData == nil && meta.AlbumPic != "" {
		imgData = fetchUrl(meta.AlbumPic)
	}

	if imgData != nil {
		picMIME := "image/jpeg"
		if containPNGHeader(imgData) {
			picMIME = "image/png"
		}
		picture, err := flacpicture.NewFromImageData(flacpicture.PictureTypeFrontCover, "Front cover", imgData, picMIME)
		if err == nil {
			picturemeta := picture.Marshal()
			f.Meta = append(f.Meta, &picturemeta)
		}
	} else if meta.AlbumPic != "" {
		picture := &flacpicture.MetadataBlockPicture{
			PictureType: flacpicture.PictureTypeFrontCover,
			MIME:        "-->",
			Description: "Front cover",
			ImageData:   []byte(meta.AlbumPic),
		}
		picturemeta := picture.Marshal()
		f.Meta = append(f.Meta, &picturemeta)
	}

	var cmtmeta *flac.MetaDataBlock
	for _, m := range f.Meta {
		if m.Type == flac.VorbisComment {
			cmtmeta = m
			break
		}
	}
	var cmts *flacvorbis.MetaDataBlockVorbisComment
	if cmtmeta != nil {
		cmts, err = flacvorbis.ParseFromMetaDataBlock(*cmtmeta)
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		cmts = flacvorbis.New()
	}

	if titles, err := cmts.Get(flacvorbis.FIELD_TITLE); err != nil {
		log.Println(err)
		return
	} else if len(titles) == 0 {
		if meta.MusicName != "" {
			// log.Println("Adding music name")
			cmts.Add(flacvorbis.FIELD_TITLE, meta.MusicName)
		}
	}

	if albums, err := cmts.Get(flacvorbis.FIELD_ALBUM); err != nil {
		log.Println(err)
		return
	} else if len(albums) == 0 {
		if meta.Album != "" {
			// log.Println("Adding album name")
			cmts.Add(flacvorbis.FIELD_ALBUM, meta.Album)
		}
	}

	if artists, err := cmts.Get(flacvorbis.FIELD_ARTIST); err != nil {
		log.Println(err)
		return
	} else if len(artists) == 0 {
		artist := func() []string {
			res := make([]string, 0)
			if len(meta.Artist) < 1 {
				return nil
			}
			for _, artist := range meta.Artist {
				res = append(res, artist[0].(string))
			}
			return res
		}()
		for _, name := range artist {
			cmts.Add(flacvorbis.FIELD_ARTIST, name)
		}
	}
	res := cmts.Marshal()
	if cmtmeta != nil {
		*cmtmeta = res
	} else {
		f.Meta = append(f.Meta, &res)
	}

	f.Save(fileName)
}

func addMP3Tag(fileName string, imgData []byte, meta *MetaInfo) {
	tag, err := id3v2.Open(fileName, id3v2.Options{Parse: true})
	if err != nil {
		log.Println(err)
		return
	}
	defer tag.Close()

	if imgData == nil && meta.AlbumPic != "" {
		imgData = fetchUrl(meta.AlbumPic)
	}

	if imgData != nil {
		picMIME := "image/jpeg"
		if containPNGHeader(imgData) {
			picMIME = "image/png"
		}
		pic := id3v2.PictureFrame{
			Encoding:    id3v2.EncodingISO,
			MimeType:    picMIME,
			PictureType: id3v2.PTFrontCover,
			Description: "Front cover",
			Picture:     imgData,
		}
		tag.AddAttachedPicture(pic)
	} else if meta.AlbumPic != "" {
		pic := id3v2.PictureFrame{
			Encoding:    id3v2.EncodingISO,
			MimeType:    "-->",
			PictureType: id3v2.PTFrontCover,
			Description: "Front cover",
			Picture:     []byte(meta.AlbumPic),
		}
		tag.AddAttachedPicture(pic)
	}

	if tag.GetTextFrame("TIT2").Text == "" {
		if meta.MusicName != "" {
			log.Println("Adding music name")
			tag.AddTextFrame("TIT2", id3v2.EncodingUTF8, meta.MusicName)
		}
	}

	if tag.GetTextFrame("TALB").Text == "" {
		if meta.Album != "" {
			log.Println("Adding album name")
			tag.AddTextFrame("TALB", id3v2.EncodingUTF8, meta.Album)
		}
	}

	if tag.GetTextFrame("TPE1").Text == "" {
		artist := func() []string {
			res := make([]string, 0)
			if len(meta.Artist) < 1 {
				return nil
			}
			for _, artist := range meta.Artist {
				res = append(res, artist[0].(string))
			}
			return res
		}()
		if artist != nil {
			log.Println("Adding artist")
			for _, name := range artist {
				tag.AddTextFrame("TPE1", id3v2.EncodingUTF8, name)
			}
		}
	}

	if err = tag.Save(); err != nil {
		log.Println(err)
	}
}

func encrypt(offset int, buf []byte, len int) int {
	if offset < 0 {
		return -1
	}
	for i := 0; i < len; i++ {
		buf[i] ^= mapL(offset + i)
	}
	return 0
}

func mapL(v int) byte {
	key := []byte{
		0x77, 0x48, 0x32, 0x73, 0xDE, 0xF2, 0xC0, 0xC8, 0x95, 0xEC, 0x30, 0xB2,
		0x51, 0xC3, 0xE1, 0xA0, 0x9E, 0xE6, 0x9D, 0xCF, 0xFA, 0x7F, 0x14, 0xD1,
		0xCE, 0xB8, 0xDC, 0xC3, 0x4A, 0x67, 0x93, 0xD6, 0x28, 0xC2, 0x91, 0x70,
		0xCA, 0x8D, 0xA2, 0xA4, 0xF0, 0x08, 0x61, 0x90, 0x7E, 0x6F, 0xA2, 0xE0,
		0xEB, 0xAE, 0x3E, 0xB6, 0x67, 0xC7, 0x92, 0xF4, 0x91, 0xB5, 0xF6, 0x6C,
		0x5E, 0x84, 0x40, 0xF7, 0xF3, 0x1B, 0x02, 0x7F, 0xD5, 0xAB, 0x41, 0x89,
		0x28, 0xF4, 0x25, 0xCC, 0x52, 0x11, 0xAD, 0x43, 0x68, 0xA6, 0x41, 0x8B,
		0x84, 0xB5, 0xFF, 0x2C, 0x92, 0x4A, 0x26, 0xD8, 0x47, 0x6A, 0x7C, 0x95,
		0x61, 0xCC, 0xE6, 0xCB, 0xBB, 0x3F, 0x47, 0x58, 0x89, 0x75, 0xC3, 0x75,
		0xA1, 0xD9, 0xAF, 0xCC, 0x08, 0x73, 0x17, 0xDC, 0xAA, 0x9A, 0xA2, 0x16,
		0x41, 0xD8, 0xA2, 0x06, 0xC6, 0x8B, 0xFC, 0x66, 0x34, 0x9F, 0xCF, 0x18,
		0x23, 0xA0, 0x0A, 0x74, 0xE7, 0x2B, 0x27, 0x70, 0x92, 0xE9, 0xAF, 0x37,
		0xE6, 0x8C, 0xA7, 0xBC, 0x62, 0x65, 0x9C, 0xC2, 0x08, 0xC9, 0x88, 0xB3,
		0xF3, 0x43, 0xAC, 0x74, 0x2C, 0x0F, 0xD4, 0xAF, 0xA1, 0xC3, 0x01, 0x64,
		0x95, 0x4E, 0x48, 0x9F, 0xF4, 0x35, 0x78, 0x95, 0x7A, 0x39, 0xD6, 0x6A,
		0xA0, 0x6D, 0x40, 0xE8, 0x4F, 0xA8, 0xEF, 0x11, 0x1D, 0xF3, 0x1B, 0x3F,
		0x3F, 0x07, 0xDD, 0x6F, 0x5B, 0x19, 0x30, 0x19, 0xFB, 0xEF, 0x0E, 0x37,
		0xF0, 0x0E, 0xCD, 0x16, 0x49, 0xFE, 0x53, 0x47, 0x13, 0x1A, 0xBD, 0xA4,
		0xF1, 0x40, 0x19, 0x60, 0x0E, 0xED, 0x68, 0x09, 0x06, 0x5F, 0x4D, 0xCF,
		0x3D, 0x1A, 0xFE, 0x20, 0x77, 0xE4, 0xD9, 0xDA, 0xF9, 0xA4, 0x2B, 0x76,
		0x1C, 0x71, 0xDB, 0x00, 0xBC, 0xFD, 0xC, 0x6C, 0xA5, 0x47, 0xF7, 0xF6,
		0x00, 0x79, 0x4A, 0x11}
	if v >= 0 {
		if v > 0x7FFF {
			v %= 0x7FFF
		}
	} else {
		v = 0
	}
	return key[(v*v+80923)%256]
}

func DecodeQQMUSIC(infile string, outfile string) bool {
	fin, err := os.Open(infile)
	if err != nil {
		log.Fatal("cannot open file: " + infile)
		return false
	}
	fout, err := os.Create(outfile)
	if err != nil {
		log.Fatal("cannot create new file: " + outfile)
		return false
	}
	defer fin.Close()
	defer fout.Close()

	stat, _ := fin.Stat()
	buf := make([]byte, stat.Size())
	fin.Read(buf)
	encrypt(0, buf, len(buf))
	fout.Write(buf)
	return true
}

func help() {
	fmt.Println("nqdump go version V1.0 ")
	fmt.Println("A tool to decode cryptoed netease music files and qqmusic files")
	fmt.Println("Support Formats: [ncm](netease) and [qmcflac/qmc0/qmc3](qqmusic)")
	fmt.Println("\tUsage:")
	fmt.Println("nqdumpgo [file1] [file2] [...]")
	fmt.Println("Coded by CRMMC, KGDsave Software Studio")
}

func main() {
	argc := len(os.Args)
	if argc <= 1 {
		help()
		return
	}
	files := make([]string, 0)

	for i := 0; i < argc-1; i++ {
		path := os.Args[i+1]
		if info, err := os.Stat(path); err != nil {
			log.Fatalf("Path %s does not exist.", info)
		} else if info.IsDir() {
			filelist, err := ioutil.ReadDir(path)
			if err != nil {
				log.Fatalf("Error while reading %s: %s", path, err.Error())
			}
			for _, f := range filelist {
				files = append(files, filepath.Join(path, "./", f.Name()))
			}
		} else {
			files = append(files, path)
		}
	}

	for _, filename := range files {
		if filepath.Ext(filename) == ".ncm" {
			log.Printf("NOW: %s: Decoding...\n", filename)
			DecodeNCM(filename)
		} else if filepath.Ext(filename) == ".qmc0" || filepath.Ext(filename) == ".qmc3" {
			log.Printf("NOW: %s: Decoding...\n", filename)
			DecodeQQMUSIC(filename, strings.Replace(strings.Replace(filename, ".qmc0", ".mp3", -1), ".qmc3", ".mp3", -1))
		} else if filepath.Ext(filename) == ".qmcflac" || filepath.Ext(filename) == ".mflac" {
			log.Printf("NOW: %s: Decoding...\n", filename)
			DecodeQQMUSIC(filename, strings.Replace(strings.Replace(filename, ".qmcflac", ".flac", -1), ".mflac", ".flac", -1))
		} else {
			log.Printf("Skipping %s: not cryptoed file found!\n", filename)
		}
	}

}
