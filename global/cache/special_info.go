package cache

func NewSpecialInfo(s []byte, iss string) *specialInfo {

	return &specialInfo{
		secret: s,
		issuer: iss,
	}
}

func GetSpecialInfo(sInfo *specialInfo) ([]byte, string) {

	return sInfo.secret, sInfo.issuer
}
