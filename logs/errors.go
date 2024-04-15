package logs

import (
	"fmt"
	"net/http"
)

type StorageError struct {
	Storage string
	Message string
}

func (e StorageError) Error() string {
	return e.Storage + ":" + e.Message
}

type NotImplemented struct {
	Message string
}

func (e NotImplemented) Error() string {
	return e.Message
}

type StorageNotSupport struct{}

func (e StorageNotSupport) Error() string {
	return "storage not support"
}

type AddressError struct {
	Message string
}

func (e AddressError) Error() string {
	return e.Message
}

type AuthenticationFailed struct {
	Message string
}

func (e AuthenticationFailed) Error() string {
	return e.Message
}

type EthError struct {
	Message string
}

func (e EthError) Error() string {
	return e.Message
}

type ContractError struct {
	Message string
}

func (e ContractError) Error() string {
	return e.Message
}

type ServerError struct {
	Message string
}

func (e ServerError) Error() string {
	return e.Message
}

type GatewayError struct {
	Message string
}

func (e GatewayError) Error() string {
	return e.Message
}

type ConfigError struct {
	Message string
}

func (e ConfigError) Error() string {
	return e.Message
}

type DataBaseError struct {
	Message string
}

func (e DataBaseError) Error() string {
	return e.Message
}

type DataStoreError struct {
	Message string
}

func (e DataStoreError) Error() string {
	return e.Message
}

type ControllerError struct {
	Message string
}

func (e ControllerError) Error() string {
	return e.Message
}

type NoPermission struct {
	Message string
}

func (e NoPermission) Error() string {
	return e.Message
}

type WalletError struct {
	Message string
}

func (e WalletError) Error() string {
	return e.Message
}

type APIError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

type APIErrorCode int

type errorCodeMap map[APIErrorCode]APIError

const (
	ErrNone APIErrorCode = iota
	ErrInternal
	ErrNotImplemented
	ErrStorage
	ErrAddress
	ErrStorageNotSupport
	ErrAuthenticationFailed
	ErrContract
	ErrEth
	ErrServer
	ErrGateway
	ErrConfig
	ErrDataBase
	ErrDataStore
	ErrController
	ErrNoPermission
	ErrWallet
)

func (e errorCodeMap) ToAPIErrWithErr(errCode APIErrorCode, err error) APIError {
	apiErr, ok := e[errCode]
	if !ok {
		apiErr = e[ErrAddress]
	}
	if err != nil {
		apiErr.Description = fmt.Sprintf("%s (%s)", apiErr.Description, err.Error())
	}
	return apiErr
}

func (e errorCodeMap) ToAPIErr(errCode APIErrorCode) APIError {
	return e.ToAPIErrWithErr(errCode, nil)
}

var ErrorCodes = errorCodeMap{
	ErrInternal: {
		Code:           "InternalError",
		Description:    "We encountered an internal error, please try again.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrNotImplemented: {
		Code:           "NotImplemented",
		Description:    "A header you provided implies functionality that is not implemented",
		HTTPStatusCode: http.StatusNotImplemented,
	},
	ErrStorage: {
		Code:           "Storage",
		Description:    "Error storing file",
		HTTPStatusCode: 516,
	},
	ErrAddress: {
		Code:           "Address",
		Description:    "Address Error",
		HTTPStatusCode: 517,
	},
	ErrStorageNotSupport: {
		Code:           "Storage",
		Description:    "Storage Error",
		HTTPStatusCode: 518,
	},
	ErrAuthenticationFailed: {
		Code:           "Authentication",
		Description:    "Authentication Failed",
		HTTPStatusCode: 401,
	},
	ErrContract: {
		Code:           "contract",
		Description:    "contract Error",
		HTTPStatusCode: 519,
	},
	ErrEth: {
		Code:           "Eth",
		Description:    "Eth Error",
		HTTPStatusCode: 520,
	},
	ErrServer: {
		Code:           "ServerError",
		Description:    "Server Error",
		HTTPStatusCode: 521,
	},
	ErrGateway: {
		Code:           "GatewayError",
		Description:    "Gateway Error",
		HTTPStatusCode: 522,
	},
	ErrConfig: {
		Code:           "ConfigError",
		Description:    "Config Error",
		HTTPStatusCode: 523,
	},
	ErrDataBase: {
		Code:           "DataBaseError",
		Description:    "DataBase Error",
		HTTPStatusCode: 524,
	},
	ErrController: {
		Code:           "ControllerError",
		Description:    "Controller Error",
		HTTPStatusCode: 525,
	},
	ErrNoPermission: {
		Code:           "Permission",
		Description:    "You don't have access to the resource",
		HTTPStatusCode: 526,
	},
	ErrWallet: {
		Code:           "Wallet",
		Description:    "Wallet error",
		HTTPStatusCode: 527,
	},
	ErrDataStore: {
		Code:           "datastore",
		Description:    "datastore error",
		HTTPStatusCode: 528,
	},
}

func ToAPIErrorCode(err error) APIError {
	if err == nil {
		return ErrorCodes.ToAPIErr(ErrNone)
	}
	var apiErr APIErrorCode

	switch err.(type) {
	case NotImplemented:
		apiErr = ErrNotImplemented
	case StorageError:
		apiErr = ErrStorage
	case AddressError:
		apiErr = ErrAddress
	case StorageNotSupport:
		apiErr = ErrStorageNotSupport
	case AuthenticationFailed:
		apiErr = ErrAuthenticationFailed
	case ContractError:
		apiErr = ErrContract
	case EthError:
		apiErr = ErrEth
	case ServerError:
		apiErr = ErrServer
	case GatewayError:
		apiErr = ErrGateway
	case ConfigError:
		apiErr = ErrConfig
	case DataBaseError:
		apiErr = ErrDataBase
	case ControllerError:
		apiErr = ErrController
	case NoPermission:
		apiErr = ErrNoPermission
	case WalletError:
		apiErr = ErrWallet
	case *DataStoreError:
		apiErr = ErrDataStore
	default:
		apiErr = ErrInternal
	}
	return ErrorCodes.ToAPIErrWithErr(apiErr, err)
}

var (
	ErrAlreadyExist = fmt.Errorf("already exist")
	ErrNotExist     = fmt.Errorf("not exist")
)

type ErrResponse struct {
	Package string
	Err     error
}
