#include<stdio.h>
#include<stdlib.h>

struct Node
{
	int val;
	struct Node *next;
};

void swap(struct Node *left, struct Node *right) {
	int tmp = left->val;
	left->val = right->val;
	right->val = tmp;
}

void bubbleSort(struct Node *head) {
	int swapped, i;
	struct Node *rptr;
	struct Node *lptr = NULL;

	if (head == NULL)
		return;

	do {
		swapped = 0;
		rptr = head;

		while (rptr->next != lptr) {
			 if (rptr->val > rptr->next->val) {
			 	swap(rptr, rptr->next);
			 	swapped = 1;
			 }
			 rptr = rptr->next;
		}
		lptr = rptr;
	}
	while (swapped);
}

//################# TEST SUITE #################//

struct Node* createNode(int val) {
	struct Node* newNode = (struct Node*)malloc(sizeof(struct Node));
	newNode->val = val;
	newNode->next = NULL;
	return newNode;
}

void insertEnd(struct Node** head, int val) {
	struct Node* newNode = createNode(val);

	if (*head == NULL) {
		*head = newNode;
		return;
	}

	struct Node* tmp = *head;
	while (tmp->next != NULL) {
		tmp = tmp->next;
	}
	tmp->next = newNode;
}

void printList(struct Node* head) {
	struct Node* temp = head;
	while (temp != NULL) {
		printf("%d ", temp->val);
		temp = temp->next;
	}
	printf("\n");
}

void freeList(struct Node* head) {
	struct Node* temp;
	while (head != NULL) {
		temp = head;
		head = head->next;
		free(temp);
	}
}

void testBubbleSort() {
	printf("Testing Bubble Sort on Linked List:\n\n");
	
	// Test Case 1: Random unsorted list
	printf("Test 1: Random unsorted list\n");
	struct Node* head1 = NULL;
	insertEnd(&head1, 64);
	insertEnd(&head1, 34);
	insertEnd(&head1, 25);
	insertEnd(&head1, 12);
	insertEnd(&head1, 22);
	insertEnd(&head1, 11);
	insertEnd(&head1, 90);
	
	printf("Original: ");
	printList(head1);
	bubbleSort(head1);
	printf("Sorted:   ");
	printList(head1);
	printf("\n");
	freeList(head1);
	
	// Test Case 2: Already sorted list
	printf("Test 2: Already sorted list\n");
	struct Node* head2 = NULL;
	insertEnd(&head2, 1);
	insertEnd(&head2, 2);
	insertEnd(&head2, 3);
	insertEnd(&head2, 4);
	insertEnd(&head2, 5);
	
	printf("Original: ");
	printList(head2);
	bubbleSort(head2);
	printf("Sorted:   ");
	printList(head2);
	printf("\n");
	freeList(head2);
	
	// Test Case 3: Reverse sorted list
	printf("Test 3: Reverse sorted list\n");
	struct Node* head3 = NULL;
	insertEnd(&head3, 5);
	insertEnd(&head3, 4);
	insertEnd(&head3, 3);
	insertEnd(&head3, 2);
	insertEnd(&head3, 1);
	
	printf("Original: ");
	printList(head3);
	bubbleSort(head3);
	printf("Sorted:   ");
	printList(head3);
	printf("\n");
	freeList(head3);
	
	// Test Case 4: List with duplicate values
	printf("Test 4: List with duplicates\n");
	struct Node* head4 = NULL;
	insertEnd(&head4, 3);
	insertEnd(&head4, 1);
	insertEnd(&head4, 4);
	insertEnd(&head4, 1);
	insertEnd(&head4, 5);
	insertEnd(&head4, 9);
	insertEnd(&head4, 2);
	insertEnd(&head4, 6);
	insertEnd(&head4, 5);
	
	printf("Original: ");
	printList(head4);
	bubbleSort(head4);
	printf("Sorted:   ");
	printList(head4);
	printf("\n");
	freeList(head4);
	
	// Test Case 5: Single element list
	printf("Test 5: Single element list\n");
	struct Node* head5 = NULL;
	insertEnd(&head5, 42);
	
	printf("Original: ");
	printList(head5);
	bubbleSort(head5);
	printf("Sorted:   ");
	printList(head5);
	printf("\n");
	freeList(head5);
	
	// Test Case 6: Empty list
	printf("Test 6: Empty list\n");
	struct Node* head6 = NULL;
	
	printf("Original: Empty list\n");
	bubbleSort(head6);
	printf("Sorted:   Empty list\n");
	printf("\n");
	
	printf("All tests completed successfully!\n");
}

int main() {
	testBubbleSort();
	return 0;
}