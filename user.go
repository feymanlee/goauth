package goauth

type User struct {
	ID            string         `json:"id"`
	Nickname      string         `json:"nickname"`
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	Avatar        string         `json:"avatar"`
	Raw           map[string]any `json:"raw"`
	TokenResponse map[string]any `json:"token_response"`
	Provider      Provider       `json:"provider"`
	AppID         string         `json:"app_id"`
	SubjectType   SubjectType    `json:"subject_type"`
	UnionID       string         `json:"union_id,omitempty"`
}

func (user User) Identity() Identity {
	return Identity{
		Provider: user.Provider, AppID: user.AppID, Subject: user.ID,
		SubjectType: user.SubjectType, UnionID: user.UnionID,
	}
}

func (user User) Key() IdentityKey {
	return user.Identity().Key()
}
