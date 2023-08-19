package typesdb


// FieldOrder is a definition of a single field sorting order.
type FieldOrder struct {
	// FieldName determines a name of the field.
	// It should match with the model name.
	FieldName  string

	// Descending determines if the field should be sorted in descending order.
	Descending bool

	// Nulls determines how null values should be sorted.
	Nulls NullFieldOrderAction
}

type FilterExpression struct {
	// Operator determines the operator that should be used to compare the field value.
	Operator LogicalOperator

	// Filters is a list of filters that should be used to filter the field value.
	Filters []FieldFilter
}


// LogicalOperator is an operator that should be used to compare the field value.
type LogicalOperator int

const (
	And LogicalOperator = iota
	Or
)


// FieldFilter is a definition of a single field filter.
type FieldFilter struct {
	// FieldName determines a name of the field.
	// It should match with the model name.
	FieldName string

	// Operator determines the operator that should be used to compare the field value.
	Operator FieldFilterOperator

	// Value is the value that should be used to compare the field value.
	Value any
}

// FieldFilterOperator is an operator that should be used to compare the field value.
type FieldFilterOperator int

const (
	Equal FieldFilterOperator = iota
	NotEqual
	GreaterThan
	GreaterThanOrEqual
	LessThan
	LessThanOrEqual
	Like
	NotLike
	In
	NotIn
)


// NullFieldOrderAction is an action that should be performed when null values are encountered.
type NullFieldOrderAction int

const (
	NullFieldOrderActionUndefined NullFieldOrderAction = iota
	NullsFirst
	NullsLast
)