package auth

import (
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// Decode one credential with the same sticky-error reader as its principals.
func (reader *cacheReader) credential(version uint8) *credentials.Credential {
	credential := &credentials.Credential{Client: reader.principal(), Server: reader.principal()}
	credential.Key.KeyType = int32(reader.u16())
	if version == 3 {
		reader.u16()
	}
	credential.Key.KeyValue = append([]byte(nil), reader.data()...)
	credential.AuthTime = reader.timestamp()
	credential.StartTime = reader.timestamp()
	credential.EndTime = reader.timestamp()
	credential.RenewTill = reader.timestamp()
	sessionKey := reader.take(1)
	credential.IsSKey = len(sessionKey) > 0 && sessionKey[0] != 0
	credential.TicketFlags = types.NewKrbFlags()
	credential.TicketFlags.Bytes = append([]byte(nil), reader.take(4)...)
	for count, index := reader.count(), 0; index < count && reader.err == nil; index++ {
		credential.Addresses = append(credential.Addresses, types.HostAddress{
			AddrType: int32(reader.u16()), Address: append([]byte(nil), reader.data()...),
		})
	}
	for count, index := reader.count(), 0; index < count && reader.err == nil; index++ {
		credential.AuthData = append(credential.AuthData, types.AuthorizationDataEntry{
			ADType: int32(reader.u16()), ADData: append([]byte(nil), reader.data()...),
		})
	}
	credential.Ticket = append([]byte(nil), reader.data()...)
	credential.SecondTicket = append([]byte(nil), reader.data()...)
	return credential
}
