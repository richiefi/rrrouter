package caching

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStorageMetadata_encoding_is_custom_format(t *testing.T) {
	s := "data.richie.app|/editions-eu/issue/3|{Accept-Encoding:[gzip, deflate],Origin:[https://x.example.com]}|{Accept-Ranges:[bytes],Access-Control-Allow-Credentials:[true]}|200|http://x|1631324460|1631557504|87489"
	sm, err := decodeStorageMetadata([]byte(s))
	require.Nil(t, err)
	s2 := encodeStorageMetadata(sm)
	require.Equal(t, []byte(s), s2)
}

func TestStorageMetadata_decoding_can_use_both_formats(t *testing.T) {
	s := "data.richie.app|/editions-eu/issue/3|{Accept-Encoding:[gzip, deflate],Origin:[https://x.example.com]}|{Accept-Ranges:[bytes],Access-Control-Allow-Credentials:[true]}|200|http://x|1631324460|1631557504|87489"
	sm, err := decodeStorageMetadata([]byte(s))
	require.Nil(t, err)
	require.Equal(t, "data.richie.app", sm.Host)
	require.Equal(t, "/editions-eu/issue/3", sm.Path)
	require.Equal(t, "gzip, deflate", sm.RequestHeader.Get("Accept-Encoding"))
	require.Equal(t, "https://x.example.com", sm.RequestHeader.Get("Origin"))
	require.Equal(t, "bytes", sm.ResponseHeader.Get("Accept-Ranges"))
	require.Equal(t, "true", sm.ResponseHeader.Get("Access-Control-Allow-Credentials"))
	require.Equal(t, 200, sm.Status)
	require.Equal(t, "http://x", sm.RedirectedURL)
	require.Equal(t, int64(1631324460), sm.Created)
	require.Equal(t, int64(1631557504), sm.Revalidated)
	require.Equal(t, int64(87489), sm.Size)
	s = "{\"Host\":\"data.richie.app\",\"Path\":\"/editions-eu/issue/3\",\"RequestHeader\":{\"Accept-Encoding\":[\"gzip, deflate\"],\"Origin\":[\"https://x.example.com\"]},\"ResponseHeader\":{\"Accept-Ranges\":[\"bytes\"],\"Access-Control-Allow-Credentials\":[\"true\"]},\"Status\":200,\"RedirectedURL\":\"http://x\",\"Created\":1631324460,\"Revalidated\":1631557504,\"Size\":87489}"
	sm, err = decodeStorageMetadata([]byte(s))
	require.Nil(t, err)
	require.Equal(t, "data.richie.app", sm.Host)
	require.Equal(t, "/editions-eu/issue/3", sm.Path)
	require.Equal(t, "gzip, deflate", sm.RequestHeader.Get("Accept-Encoding"))
	require.Equal(t, "https://x.example.com", sm.RequestHeader.Get("Origin"))
	require.Equal(t, "bytes", sm.ResponseHeader.Get("Accept-Ranges"))
	require.Equal(t, "true", sm.ResponseHeader.Get("Access-Control-Allow-Credentials"))
	require.Equal(t, 200, sm.Status)
	require.Equal(t, "http://x", sm.RedirectedURL)
	require.Equal(t, int64(1631324460), sm.Created)
	require.Equal(t, int64(1631557504), sm.Revalidated)
	require.Equal(t, int64(87489), sm.Size)
}

func Benchmark_deserialize_custom(b *testing.B) {
	bs := []byte("data.richie.app|/editions-eu/issue/3/6/8/issue_36893589-3bbd-4752-b79c-a9a9407283cf_issue/issue_html5_splitjpg_768.tar/3eb05c6b-ff98-4b1c-96d8-a48e1c8e42de_p0/page.jpg|{Accept-Encoding:[gzip, deflate],Origin:[https://lapinkansa.ap.richiefi.net]}|{Accept-Ranges:[bytes],Access-Control-Allow-Credentials:[true],Access-Control-Allow-Origin:[*],Access-Control-Expose-Headers:[Date, Etag, Server, Connection, Accept-Ranges, Content-Range, Content-Encoding, Content-Length, Content-Type, Content-Disposition, Last-Modified, Content-Language, Cache-Control, Retry-After, X-Amz-Bucket-Region, Expires, X-Amz*, X-Amz*, *],Age:[0],Cache-Control:[max-age=86400, s-maxage=86400],Content-Length:[87489],Content-Security-Policy:[block-all-mixed-content],Content-Type:[image/jpeg],Date:[Sat, 11 Sep 2021 01:40:48 GMT],Etag:[\"177540aa32ab56d74db5969495810b6c\"],Last-Modified:[Fri, 10 Sep 2021 19:29:49 GMT],Server:[MinIO],Timing-Allow-Origin:[*],Vary:[Origin],X-Amz-Request-Id:[16A3A0F175150540],X-Xss-Protection:[1; mode=block]}|200|\"\"|1631324460|1631557504|87489")
	cm := StorageMetadata{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeCustom(&cm, &bs)
	}
	s2 := encodeCustom(&cm)
	require.Equal(b, string(bs), s2)
}

func Benchmark_deserialize_json(b *testing.B) {
	s := "{\"Host\":\"data.richie.app\",\"Path\":\"/editions-eu/issue/3/6/8/issue_36893589-3bbd-4752-b79c-a9a9407283cf_issue/issue_html5_splitjpg_768.tar/3eb05c6b-ff98-4b1c-96d8-a48e1c8e42de_p0/page.jpg\",\"RequestHeader\":{\"Accept-Encoding\":[\"gzip, deflate\"],\"Origin\":[\"https://lapinkansa.ap.richiefi.net\"]},\"ResponseHeader\":{\"Accept-Ranges\":[\"bytes\"],\"Access-Control-Allow-Credentials\":[\"true\"],\"Access-Control-Allow-Origin\":[\"*\"],\"Access-Control-Expose-Headers\":[\"Date, Etag, Server, Connection, Accept-Ranges, Content-Range, Content-Encoding, Content-Length, Content-Type, Content-Disposition, Last-Modified, Content-Language, Cache-Control, Retry-After, X-Amz-Bucket-Region, Expires, X-Amz*, X-Amz*, *\"],\"Age\":[\"0\"],\"Cache-Control\":[\"max-age=86400, s-maxage=86400\"],\"Content-Length\":[\"87489\"],\"Content-Security-Policy\":[\"block-all-mixed-content\"],\"Content-Type\":[\"image/jpeg\"],\"Date\":[\"Sat, 11 Sep 2021 01:40:48 GMT\"],\"Etag\":[\"\\\"177540aa32ab56d74db5969495810b6c\\\"\"],\"Last-Modified\":[\"Fri, 10 Sep 2021 19:29:49 GMT\"],\"Server\":[\"MinIO\"],\"Timing-Allow-Origin\":[\"*\"],\"Vary\":[\"Origin\"],\"X-Amz-Request-Id\":[\"16A3A0F175150540\"],\"X-Xss-Protection\":[\"1; mode=block\"]},\"Status\":200,\"RedirectedURL\":\"\",\"Created\":1631324460,\"Revalidated\":1631557504,\"Size\":87489}"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeStorageMetadata([]byte(s))
	}
}
